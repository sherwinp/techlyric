using System;
using System.Collections.Specialized;
using System.Configuration;
using System.Configuration.Provider;
using System.Data;
using System.Data.SQLite;
using System.Web.Security;

namespace SQLiteProviders
{
	/// <summary>
	/// Provides a Role implementation whose data is stored in a SQLite database.
	/// </summary>
	public sealed class SQLiteRoleProvider : RoleProvider
	{
		#region Private Fields

		private const string _httpTransactionId = "SQLiteTran";
		private const string APP_TB_NAME = "[aspnet_Applications]";
		private const string ROLE_TB_NAME = "[aspnet_Roles]";
		private const string USER_TB_NAME = "[aspnet_Users]";
		private const string USERS_IN_ROLES_TB_NAME = "[aspnet_UsersInRoles]";
		private const int MAX_USERNAME_LENGTH = 256;
		private const int MAX_ROLENAME_LENGTH = 256;
		private const int MAX_APPLICATION_NAME_LENGTH = 256;

		private static string _applicationName;
		private static string _applicationId;
		private static string _connectionString;

		#endregion

		#region Public Properties

		/// <summary>
		/// Gets or sets the name of the application to store and retrieve role information for.
		/// </summary>
		/// <value></value>
		/// <returns>
		/// The name of the application to store and retrieve role information for.
		/// </returns>
		public override string ApplicationName
		{
			get { return _applicationName; }
			set
			{
				if (value.Length > MAX_APPLICATION_NAME_LENGTH)
					throw new ProviderException(String.Format("ApplicationName exceeds {0} characters.", MAX_APPLICATION_NAME_LENGTH));

				_applicationName = value;
				_applicationId = GetApplicationId(_applicationName);
			}
		}

		#endregion

		#region Public Methods

		/// <summary>
		/// Initializes the provider.
		/// </summary>
		/// <param name="name">The friendly name of the provider.</param>
		/// <param name="config">A collection of the name/value pairs representing the provider-specific attributes specified in the configuration for this provider.</param>
		/// <exception cref="T:System.ArgumentNullException">
		/// The name of the provider is null.
		/// </exception>
		/// <exception cref="T:System.ArgumentException">
		/// The name of the provider has a length of zero.
		/// </exception>
		/// <exception cref="T:System.InvalidOperationException">
		/// An attempt is made to call <see cref="M:System.Configuration.Provider.ProviderBase.Initialize(System.String,System.Collections.Specialized.NameValueCollection)"/> on a provider after the provider has already been initialized.
		/// </exception>
		public override void Initialize(string name, NameValueCollection config)
		{
			// Initialize values from web.config.
			if (config == null)
				throw new ArgumentNullException("config");

			if (name == null || name.Length == 0)
				name = "SQLiteRoleProvider";

			if (String.IsNullOrEmpty(config["description"]))
			{
				config.Remove("description");
				config.Add("description", "SQLite Role provider");
			}

			// Initialize the abstract base class.
			base.Initialize(name, config);

			if (config["applicationName"] == null || config["applicationName"].Trim() == "")
			{
				_applicationName = System.Web.Hosting.HostingEnvironment.ApplicationVirtualPath;
			}
			else
			{
				_applicationName = config["applicationName"];
			}

			// Initialize SQLiteConnection.
			ConnectionStringSettings connectionStringSettings = ConfigurationManager.ConnectionStrings[config["connectionStringName"]];

			if (connectionStringSettings == null || connectionStringSettings.ConnectionString.Trim() == "")
			{
				throw new ProviderException("Connection string cannot be blank.");
			}

			_connectionString = connectionStringSettings.ConnectionString;

			_applicationId = GetApplicationId(_applicationName);

			VerifyApplication();
		}

		/// <summary>
		/// Adds the specified user names to the specified roles for the configured applicationName.
		/// </summary>
		/// <param name="usernames">A string array of user names to be added to the specified roles.</param>
		/// <param name="roleNames">A string array of the role names to add the specified user names to.</param>
		public override void AddUsersToRoles(string[] usernames, string[] roleNames)
		{
			foreach (string roleName in roleNames)
			{
				if (!RoleExists(roleName))
				{
					throw new ProviderException("Role name not found.");
				}
			}

			foreach (string username in usernames)
			{
				if (username.IndexOf(',') > 0)
				{
					throw new ArgumentException("User names cannot contain commas.");
				}

				foreach (string RoleName in roleNames)
				{
					if (IsUserInRole(username, RoleName))
					{
						throw new ProviderException("User is already in role.");
					}
				}
			}

			SQLiteTransaction tran = null;
			SQLiteConnection cn = GetDBConnectionForRole();
			try
			{
				if (cn.State == ConnectionState.Closed)
					cn.Open();

				if (!IsTransactionInProgress())
					tran = cn.BeginTransaction();

				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "INSERT INTO " + USERS_IN_ROLES_TB_NAME
						+ " (UserId, RoleId)"
						+ " SELECT u.UserId, r.RoleId"
						+ " FROM " + USER_TB_NAME + " u, " + ROLE_TB_NAME + " r"
						+ " WHERE (u.LoweredUsername = $Username) AND (u.ApplicationId = $ApplicationId)"
						+ " AND (r.LoweredRoleName = $RoleName) AND (r.ApplicationId = $ApplicationId)";

					SQLiteParameter userParm = cmd.Parameters.Add("$Username", DbType.String, MAX_USERNAME_LENGTH);
					SQLiteParameter roleParm = cmd.Parameters.Add("$RoleName", DbType.String, MAX_ROLENAME_LENGTH);
					cmd.Parameters.AddWithValue("$ApplicationId", _applicationId);

					foreach (string username in usernames)
					{
						foreach (string roleName in roleNames)
						{
							userParm.Value = username.ToLowerInvariant();
							roleParm.Value = roleName.ToLowerInvariant();
							cmd.ExecuteNonQuery();
						}
					}

					// Commit the transaction if it's the one we created in this method.
					if (tran != null)
						tran.Commit();
				}
			}
			catch
			{
				if (tran != null)
					tran.Rollback();
				throw;
			}
			finally
			{
				if (tran != null)
					tran.Dispose();

				if (!IsTransactionInProgress())
					cn.Dispose();
			}
		}

		/// <summary>
		/// Adds a new role to the data source for the configured applicationName.
		/// </summary>
		/// <param name="roleName">The name of the role to create.</param>
		public override void CreateRole(string roleName)
		{
			if (roleName.IndexOf(',') > 0)
			{
				throw new ArgumentException("Role names cannot contain commas.");
			}

			if (RoleExists(roleName))
			{
				throw new ProviderException("Role name already exists.");
			}

			if (!SecUtility.ValidateParameter(ref roleName, true, true, false, MAX_ROLENAME_LENGTH))
			{
				throw new ProviderException(String.Format("The role name is too long: it must not exceed {0} chars in length.", MAX_ROLENAME_LENGTH));
			}

			SQLiteConnection cn = GetDBConnectionForRole();
			try
			{
				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "INSERT INTO " + ROLE_TB_NAME
						+ " (RoleId, RoleName, LoweredRoleName, ApplicationId) "
						+ " Values ($RoleId, $RoleName, $LoweredRoleName, $ApplicationId)";

					cmd.Parameters.AddWithValue("$RoleId", Guid.NewGuid().ToString());
					cmd.Parameters.AddWithValue("$RoleName", roleName);
					cmd.Parameters.AddWithValue("$LoweredRoleName", roleName.ToLowerInvariant());
					cmd.Parameters.AddWithValue("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open();

					cmd.ExecuteNonQuery();
				}
			}
			finally
			{
				if (!IsTransactionInProgress())
					cn.Dispose();
			}
		}

		/// <summary>
		/// Removes a role from the data source for the configured applicationName.
		/// </summary>
		/// <param name="roleName">The name of the role to delete.</param>
		/// <param name="throwOnPopulatedRole">If true, throw an exception if <paramref name="roleName"/> has one or more members and do not delete <paramref name="roleName"/>.</param>
		/// <returns>
		/// true if the role was successfully deleted; otherwise, false.
		/// </returns>
		public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
		{
			if (!RoleExists(roleName))
			{
				throw new ProviderException("Role does not exist.");
			}

			if (throwOnPopulatedRole && GetUsersInRole(roleName).Length > 0)
			{
				throw new ProviderException("Cannot delete a populated role.");
			}

			SQLiteTransaction tran = null;
			SQLiteConnection cn = GetDBConnectionForRole();
			try
			{
				if (cn.State == ConnectionState.Closed)
					cn.Open();

				if (!IsTransactionInProgress())
					tran = cn.BeginTransaction();

				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "DELETE FROM " + USERS_IN_ROLES_TB_NAME + " WHERE (RoleId IN"
														 + " (SELECT RoleId FROM " + ROLE_TB_NAME + " WHERE LoweredRoleName = $RoleName))";

					cmd.Parameters.AddWithValue("$RoleName", roleName.ToLowerInvariant());

					cmd.ExecuteNonQuery();
				}

				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "DELETE FROM " + ROLE_TB_NAME + " WHERE LoweredRoleName = $RoleName AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue("$RoleName", roleName.ToLowerInvariant());
					cmd.Parameters.AddWithValue("$ApplicationId", _applicationId);

					cmd.ExecuteNonQuery();
				}

				// Commit the transaction if it's the one we created in this method.
				if (tran != null)
					tran.Commit();
			}
			catch
			{
				if (tran != null)
					tran.Rollback();

				throw;
			}
			finally
			{
				if (tran != null)
					tran.Dispose();

				if (!IsTransactionInProgress())
					cn.Dispose();
			}

			return true;
		}

		/// <summary>
		/// Gets a list of all the roles for the configured applicationName.
		/// </summary>
		/// <returns>
		/// A string array containing the names of all the roles stored in the data source for the configured applicationName.
		/// </returns>
		public override string[] GetAllRoles()
		{
			string tmpRoleNames = String.Empty;

			SQLiteConnection cn = GetDBConnectionForRole();
			try
			{
				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "SELECT RoleName FROM " + ROLE_TB_NAME + " WHERE ApplicationId = $ApplicationId";
					cmd.Parameters.AddWithValue("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open();

					using (SQLiteDataReader dr = cmd.ExecuteReader())
					{
						while (dr.Read())
						{
							tmpRoleNames += dr.GetString(0) + ",";
						}
					}
				}
			}
			finally
			{
				if (!IsTransactionInProgress())
					cn.Dispose();
			}

			if (tmpRoleNames.Length > 0)
			{
				// Remove trailing comma.
				tmpRoleNames = tmpRoleNames.Substring(0, tmpRoleNames.Length - 1);
				return tmpRoleNames.Split(',');
			}

			return new string[0];
		}

		/// <summary>
		/// Gets a list of the roles that a specified user is in for the configured applicationName.
		/// </summary>
		/// <param name="username">The user to return a list of roles for.</param>
		/// <returns>
		/// A string array containing the names of all the roles that the specified user is in for the configured applicationName.
		/// </returns>
		public override string[] GetRolesForUser(string username)
		{
			string tmpRoleNames = String.Empty;

			SQLiteConnection cn = GetDBConnectionForRole();
			try
			{
				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "SELECT r.RoleName FROM " + ROLE_TB_NAME + " r INNER JOIN " + USERS_IN_ROLES_TB_NAME
						+ " uir ON r.RoleId = uir.RoleId INNER JOIN " + USER_TB_NAME + " u ON uir.UserId = u.UserId"
						+ " WHERE (u.LoweredUsername = $Username) AND (u.ApplicationId = $ApplicationId)";

					cmd.Parameters.AddWithValue("$Username", username.ToLowerInvariant());
					cmd.Parameters.AddWithValue("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open();

					using (SQLiteDataReader dr = cmd.ExecuteReader())
					{
						while (dr.Read())
						{
							tmpRoleNames += dr.GetString(0) + ",";
						}
					}
				}
			}
			finally
			{
				if (!IsTransactionInProgress())
					cn.Dispose();
			}

			if (tmpRoleNames.Length > 0)
			{
				// Remove trailing comma.
				tmpRoleNames = tmpRoleNames.Substring(0, tmpRoleNames.Length - 1);
				return tmpRoleNames.Split(',');
			}

			return new string[0];
		}

		/// <summary>
		/// Gets the users in role.
		/// </summary>
		/// <param name="roleName">Name of the role.</param>
		/// <returns>Returns the users in role.</returns>
		public override string[] GetUsersInRole(string roleName)
		{
			string tmpUserNames = String.Empty;

			SQLiteConnection cn = GetDBConnectionForRole();
			try
			{
				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "SELECT u.Username FROM " + USER_TB_NAME + " u INNER JOIN " + USERS_IN_ROLES_TB_NAME
						+ " uir ON u.UserId = uir.UserId INNER JOIN " + ROLE_TB_NAME + " r ON uir.RoleId = r.RoleId"
						+ " WHERE (r.LoweredRoleName = $RoleName) AND (r.ApplicationId = $ApplicationId)";

					cmd.Parameters.AddWithValue("$RoleName", roleName.ToLowerInvariant());
					cmd.Parameters.AddWithValue("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open();

					using (SQLiteDataReader dr = cmd.ExecuteReader())
					{
						while (dr.Read())
						{
							tmpUserNames += dr.GetString(0) + ",";
						}
					}
				}
			}
			finally
			{
				if (!IsTransactionInProgress())
					cn.Dispose();
			}

			if (tmpUserNames.Length > 0)
			{
				// Remove trailing comma.
				tmpUserNames = tmpUserNames.Substring(0, tmpUserNames.Length - 1);
				return tmpUserNames.Split(',');
			}

			return new string[0];
		}

		/// <summary>
		/// Gets a value indicating whether the specified user is in the specified role for the configured applicationName.
		/// </summary>
		/// <param name="username">The user name to search for.</param>
		/// <param name="roleName">The role to search in.</param>
		/// <returns>
		/// true if the specified user is in the specified role for the configured applicationName; otherwise, false.
		/// </returns>
		public override bool IsUserInRole(string username, string roleName)
		{
			SQLiteConnection cn = GetDBConnectionForRole();
			try
			{
				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "SELECT COUNT(*) FROM " + USERS_IN_ROLES_TB_NAME + " uir INNER JOIN "
						+ USER_TB_NAME + " u ON uir.UserId = u.UserId INNER JOIN " + ROLE_TB_NAME + " r ON uir.RoleId = r.RoleId "
						+ " WHERE u.LoweredUsername = $Username AND u.ApplicationId = $ApplicationId"
						+ " AND r.LoweredRoleName = $RoleName AND r.ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue("$Username", username.ToLowerInvariant());
					cmd.Parameters.AddWithValue("$RoleName", roleName.ToLowerInvariant());
					cmd.Parameters.AddWithValue("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open();

					return (Convert.ToInt64(cmd.ExecuteScalar()) > 0);
				}
			}
			finally
			{
				if (!IsTransactionInProgress())
					cn.Dispose();
			}
		}

		/// <summary>
		/// Removes the specified user names from the specified roles for the configured applicationName.
		/// </summary>
		/// <param name="usernames">A string array of user names to be removed from the specified roles.</param>
		/// <param name="roleNames">A string array of role names to remove the specified user names from.</param>
		public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
		{
			foreach (string roleName in roleNames)
			{
				if (!RoleExists(roleName))
				{
					throw new ProviderException("Role name not found.");
				}
			}

			foreach (string username in usernames)
			{
				foreach (string roleName in roleNames)
				{
					if (!IsUserInRole(username, roleName))
					{
						throw new ProviderException("User is not in role.");
					}
				}
			}

			SQLiteTransaction tran = null;
			SQLiteConnection cn = GetDBConnectionForRole();
			try
			{
				if (cn.State == ConnectionState.Closed)
					cn.Open();

				if (!IsTransactionInProgress())
					tran = cn.BeginTransaction();

				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "DELETE FROM " + USERS_IN_ROLES_TB_NAME
						+ " WHERE UserId = (SELECT UserId FROM " + USER_TB_NAME + " WHERE LoweredUsername = $Username AND ApplicationId = $ApplicationId)"
						+ " AND RoleId = (SELECT RoleId FROM " + ROLE_TB_NAME + " WHERE LoweredRoleName = $RoleName AND ApplicationId = $ApplicationId)";

					SQLiteParameter userParm = cmd.Parameters.Add("$Username", DbType.String, MAX_USERNAME_LENGTH);
					SQLiteParameter roleParm = cmd.Parameters.Add("$RoleName", DbType.String, MAX_ROLENAME_LENGTH);
					cmd.Parameters.AddWithValue("$ApplicationId", _applicationId);

					foreach (string username in usernames)
					{
						foreach (string roleName in roleNames)
						{
							userParm.Value = username.ToLowerInvariant();
							roleParm.Value = roleName.ToLowerInvariant();
							cmd.ExecuteNonQuery();
						}
					}

					// Commit the transaction if it's the one we created in this method.
					if (tran != null)
						tran.Commit();
				}
			}
			catch
			{
				if (tran != null)
					tran.Rollback();

				throw;
			}
			finally
			{
				if (tran != null)
					tran.Dispose();

				if (!IsTransactionInProgress())
					cn.Dispose();
			}
		}

		/// <summary>
		/// Gets a value indicating whether the specified role name already exists in the role data source for the configured applicationName.
		/// </summary>
		/// <param name="roleName">The name of the role to search for in the data source.</param>
		/// <returns>
		/// true if the role name already exists in the data source for the configured applicationName; otherwise, false.
		/// </returns>
		public override bool RoleExists(string roleName)
		{
			SQLiteConnection cn = GetDBConnectionForRole();
			try
			{
				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "SELECT COUNT(*) FROM " + ROLE_TB_NAME +
								" WHERE LoweredRoleName = $RoleName AND ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue("$RoleName", roleName.ToLowerInvariant());
					cmd.Parameters.AddWithValue("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open();

					return (Convert.ToInt64(cmd.ExecuteScalar()) > 0);
				}
			}
			finally
			{
				if (!IsTransactionInProgress())
					cn.Dispose();
			}
		}

		/// <summary>
		/// Gets an array of user names in a role where the user name contains the specified user name to match.
		/// </summary>
		/// <param name="roleName">The role to search in.</param>
		/// <param name="usernameToMatch">The user name to search for.</param>
		/// <returns>
		/// A string array containing the names of all the users where the user name matches <paramref name="usernameToMatch"/> and the user is a member of the specified role.
		/// </returns>
		public override string[] FindUsersInRole(string roleName, string usernameToMatch)
		{
			string tmpUserNames = String.Empty;

			SQLiteConnection cn = GetDBConnectionForRole();
			try
			{
				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "SELECT u.Username FROM " + USERS_IN_ROLES_TB_NAME + " uir INNER JOIN " + USER_TB_NAME
						+ " u ON uir.UserId = u.UserId INNER JOIN " + ROLE_TB_NAME + " r ON r.RoleId = uir.RoleId"
						+ " WHERE u.LoweredUsername LIKE $UsernameSearch AND r.LoweredRoleName = $RoleName AND u.ApplicationId = $ApplicationId"
						+ " AND r.ApplicationId = $ApplicationId";

					cmd.Parameters.AddWithValue("$UsernameSearch", usernameToMatch);
					cmd.Parameters.AddWithValue("$RoleName", roleName.ToLowerInvariant());
					cmd.Parameters.AddWithValue("$ApplicationId", _applicationId);

					if (cn.State == ConnectionState.Closed)
						cn.Open();

					using (SQLiteDataReader dr = cmd.ExecuteReader())
					{
						while (dr.Read())
						{
							tmpUserNames += dr.GetString(0) + ",";
						}
					}
				}
			}
			finally
			{
				if (!IsTransactionInProgress())
					cn.Dispose();
			}

			if (tmpUserNames.Length > 0)
			{
				// Remove trailing comma.
				tmpUserNames = tmpUserNames.Substring(0, tmpUserNames.Length - 1);
				return tmpUserNames.Split(',');
			}

			return new string[0];
		}

		#endregion

		#region Private Methods

		private static string GetApplicationId(string appName)
		{
			SQLiteConnection cn = GetDBConnectionForRole();
			try
			{
				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "SELECT ApplicationId FROM aspnet_Applications WHERE ApplicationName = $AppName";
					cmd.Parameters.AddWithValue("$AppName", appName);

					if (cn.State == ConnectionState.Closed)
						cn.Open();

					return cmd.ExecuteScalar() as string;
				}
			}
			finally
			{
				if (!IsTransactionInProgress())
					cn.Dispose();
			}
		}

		private static void VerifyApplication()
		{
			// Verify a record exists in the application table.
			if (!String.IsNullOrEmpty(_applicationId))
				return;

			// No record exists in the application table. Create one now.
			SQLiteConnection cn = GetDBConnectionForRole();
			try
			{
				using (SQLiteCommand cmd = cn.CreateCommand())
				{
					cmd.CommandText = "INSERT INTO " + APP_TB_NAME + " (ApplicationId, ApplicationName, Description) VALUES ($ApplicationId, $ApplicationName, $Description)";

					_applicationId = Guid.NewGuid().ToString();
					cmd.Parameters.AddWithValue("$ApplicationId", _applicationId);
					cmd.Parameters.AddWithValue("ApplicationName", _applicationName);
					cmd.Parameters.AddWithValue("Description", String.Empty);

					if (cn.State == ConnectionState.Closed)
						cn.Open();

					cmd.ExecuteNonQuery();
				}
			}
			finally
			{
				if (!IsTransactionInProgress())
					cn.Dispose();
			}
		}

		/// <summary>
		/// Get a reference to the database connection used for Role. If a transaction is currently in progress, and the
		/// connection string of the transaction connection is the same as the connection string for the Role provider,
		/// then the connection associated with the transaction is returned, and it will already be open. If no transaction is in progress,
		/// a new <see cref="SQLiteConnection"/> is created and returned. It will be closed and must be opened by the caller
		/// before using.
		/// </summary>
		/// <returns>A <see cref="SQLiteConnection"/> object.</returns>
		/// <remarks>The transaction is stored in <see cref="System.Web.HttpContext.Current"/>. That means transaction support is limited
		/// to web applications. For other types of applications, there is no transaction support unless this code is modified.</remarks>
		[System.Diagnostics.CodeAnalysis.SuppressMessage("Microsoft.Design", "CA1024:UsePropertiesWhereAppropriate")]
		private static SQLiteConnection GetDBConnectionForRole()
		{
			// Look in the HTTP context bag for a previously created connection and transaction. Return if found and its connection
			// string matches that of the Role connection string; otherwise return a fresh connection.
			if (System.Web.HttpContext.Current != null)
			{
				const string _httpTransactionId = "SQLiteTran";
				SQLiteTransaction tran = (SQLiteTransaction)System.Web.HttpContext.Current.Items[_httpTransactionId];
				if ((tran != null) && (String.Equals(tran.Connection.ConnectionString, _connectionString)))
					return tran.Connection;
			}

			return new SQLiteConnection(_connectionString);
		}

		/// <summary>
		/// Determines whether a database transaction is in progress for the Role provider.
		/// </summary>
		/// <returns>
		/// 	<c>true</c> if a database transaction is in progress; otherwise, <c>false</c>.
		/// </returns>
		/// <remarks>A transaction is considered in progress if an instance of <see cref="SQLiteTransaction"/> is found in the
		/// <see cref="System.Web.HttpContext.Current"/> Items property and its connection string is equal to the Role 
		/// provider's connection string. Note that this implementation of <see cref="SQLiteRoleProvider"/> never adds a 
		/// <see cref="SQLiteTransaction"/> to <see cref="System.Web.HttpContext.Current"/>, but it is possible that 
		/// another data provider in this application does. This may be because other data is also stored in this SQLite database,
		/// and the application author wants to provide transaction support across the individual providers. If an instance of
		/// <see cref="System.Web.HttpContext.Current"/> does not exist (for example, if the calling application is not a web application),
		/// this method always returns false.</remarks>
		private static bool IsTransactionInProgress()
		{
			if (System.Web.HttpContext.Current == null)
				return false;

			SQLiteTransaction tran = (SQLiteTransaction)System.Web.HttpContext.Current.Items[_httpTransactionId];

			if ((tran != null) && (String.Equals(tran.Connection.ConnectionString, _connectionString)))
				return true;
			else
				return false;
		}

		#endregion
	}
}