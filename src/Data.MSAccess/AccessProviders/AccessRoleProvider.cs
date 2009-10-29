//------------------------------------------------------------------------------
// <copyright file="AccessRoleProvider.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

namespace AccessProviders
{
    using System;
    using System.Web;
    using System.Web.Configuration;
    using System.Web.Security;
    using System.Security.Principal;
    using System.Security.Permissions;
    using System.Globalization;
    using System.Runtime.Serialization;
    using System.Collections;
    using System.Collections.Specialized;
    using System.Data;
    using System.Data.SqlClient;
    using System.Data.SqlTypes;
    using System.Text;
    using System.Configuration.Provider;
    using System.Configuration;
    using System.Data.OleDb;
    using System.Web.DataAccess;
    using System.Web.Hosting;
    using System.Web.Util;

    public class AccessRoleProvider : RoleProvider
    {
        private string _AppName;
        private string _DatabaseFileName;
        private int _ApplicationId = 0;
        private DateTime _ApplicationIDCacheDate;

        ////////////////////////////////////////////////////////////
        // Public properties

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("config");
            if (String.IsNullOrEmpty(name))
                name = "AccessRoleProvider";
            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "AccessProviders Role Provider");
            }
            base.Initialize(name, config);

            _DatabaseFileName = config["connectionStringName"];
            if (_DatabaseFileName == null || _DatabaseFileName.Length < 1)
                throw new ProviderException("Connection name not specified");

            string temp = AccessConnectionHelper.GetFileNameFromConnectionName(_DatabaseFileName, true);
            if (temp == null || temp.Length < 1)
            {
                throw new ProviderException("Connection string not found: " + _DatabaseFileName);
            }
            _DatabaseFileName = temp;
            //HandlerBase.CheckAndReadRegistryValue(ref _DatabaseFileName, true);
            AccessConnectionHelper.CheckConnectionString(_DatabaseFileName);

            _AppName = config["applicationName"];
            if (string.IsNullOrEmpty(_AppName))
                _AppName = SecUtility.GetDefaultAppName();

            if (_AppName.Length > 255)
            {
                throw new ProviderException("Provider application name too long, max is 255.");
            }

            config.Remove("connectionStringName");
            config.Remove("applicationName");
            config.Remove("description");
            if (config.Count > 0)
            {
                string attribUnrecognized = config.GetKey(0);
                if (!String.IsNullOrEmpty(attribUnrecognized))
                    throw new ProviderException("Provider unrecognized attribute: " + attribUnrecognized);
            }
        }


        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override bool IsUserInRole(string username, string roleName)
        {
            SecUtility.CheckParameter(ref username, true, false, true, 255, "username");
            if (username.Length < 1)
                return false;
            SecUtility.CheckParameter(ref roleName, true, true, true, 255, "roleName");

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            try
            {
                try
                {
                    int appId = GetApplicationId(holder);
                    int userId = AccessConnectionHelper.GetUserID(connection, appId, username, false);
                    int roleId = GetRoleId(connection, appId, roleName);

                    OleDbCommand command;

                    if (userId == 0)
                    {
                        return false;
                    }

                    if (roleId == 0)
                    {
                        return false;
                    }

                    command = new OleDbCommand(@"SELECT UserId FROM aspnet_UsersInRoles WHERE UserId = @UserId AND RoleId = @RoleId", connection);
                    command.Parameters.Add(new OleDbParameter("@UserId", userId));
                    command.Parameters.Add(new OleDbParameter("@RoleId", roleId));

                    object result = command.ExecuteScalar();

                    if (result == null || !(result is int) || ((int)result) != userId)
                        return false;
                    return true;
                }
                catch (Exception e)
                {
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    holder.Close();
                }
            }
            catch
            {
                throw;
            }
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override string[] GetRolesForUser(string username)
        {
            SecUtility.CheckParameter(ref username, true, false, true, 255, "username");
            if (username.Length < 1)
                return new string[0];

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            OleDbDataReader reader = null;

            try
            {
                try
                {
                    int appId = GetApplicationId(holder);
                    int userId = AccessConnectionHelper.GetUserID(connection, appId, username, false);

                    if (userId == 0)
                    {
                        return new string[0];
                    }

                    OleDbCommand command;
                    StringCollection sc = new StringCollection();
                    String[] strReturn;


                    command = new OleDbCommand(@"SELECT RoleName FROM aspnet_UsersInRoles ur, aspnet_Roles r " +
                                                @"WHERE ur.UserId = @UserId AND ur.RoleId = r.RoleId " +
                                                @"ORDER BY RoleName",
                                               connection);
                    command.Parameters.Add(new OleDbParameter("@UserId", userId));
                    reader = command.ExecuteReader(CommandBehavior.SequentialAccess);
                    while (reader.Read())
                        sc.Add(reader.GetString(0));
                    strReturn = new String[sc.Count];
                    sc.CopyTo(strReturn, 0);
                    return strReturn;
                }
                catch (Exception e)
                {
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    if (reader != null)
                        reader.Close();
                    holder.Close();
                }
            }
            catch
            {
                throw;
            }
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override void CreateRole(string roleName)
        {
            SecUtility.CheckParameter(ref roleName, true, true, true, 255, "roleName");

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            bool fBeginTransCalled = false;
            try
            {
                try
                {
                    int appId = GetApplicationId(holder);
                    OleDbCommand command;
                    int roleId = GetRoleId(connection, appId, roleName);

                    if (roleId != 0)
                    {
                        throw new ProviderException("Provider role already exists: " + roleName);
                    }

                    command = new OleDbCommand("BEGIN TRANSACTION", connection);
                    command.ExecuteNonQuery();
                    fBeginTransCalled = true;
                    command = new OleDbCommand(@"INSERT INTO aspnet_Roles (ApplicationId, RoleName) VALUES (@AppId, @RName)", connection);
                    command.Parameters.Add(new OleDbParameter("@AppId", appId));
                    command.Parameters.Add(new OleDbParameter("@RName", roleName));
                    int returnValue = command.ExecuteNonQuery();
                    command = new OleDbCommand("COMMIT TRANSACTION", connection);
                    command.ExecuteNonQuery();
                    fBeginTransCalled = false;

                    if (returnValue == 1)
                        return;
                    throw new ProviderException("Unknown provider failure");
                }
                catch (Exception e)
                {
                    if (fBeginTransCalled)
                    {
                        try
                        {
                            OleDbCommand command = new OleDbCommand("ROLLBACK TRANSACTION", connection);
                            command.ExecuteNonQuery();
                        }
                        catch { }
                    }
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    holder.Close();
                }
            }
            catch
            {
                throw;
            }
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override bool DeleteRole(string roleName, bool throwOnPopulatedRole)
        {
            SecUtility.CheckParameter(ref roleName, true, true, true, 255, "roleName");
            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            bool fBeginTransCalled = false;
            try
            {
                try
                {
                    int appId = GetApplicationId(holder);
                    OleDbCommand command;
                    int roleId = GetRoleId(connection, appId, roleName);

                    if (roleId == 0)
                    {
                        return false;
                    }

                    if (throwOnPopulatedRole)
                    {
                        command = new OleDbCommand(@"SELECT COUNT(*) " +
                                               @"FROM aspnet_UsersInRoles ur, aspnet_Users u " +
                                               @"WHERE ur.RoleId = @RoleId AND ur.UserId = u.UserId",
                                            connection);

                        command.Parameters.Add(new OleDbParameter("@RoleId", roleId));
                        object num = command.ExecuteScalar();
                        if (!(num is int) || ((int)num) != 0)
                            throw new ProviderException("Role is not empty");
                    }

                    command = new OleDbCommand("BEGIN TRANSACTION", connection);
                    command.ExecuteNonQuery();
                    fBeginTransCalled = true;
                    command = new OleDbCommand(@"DELETE FROM aspnet_Roles WHERE RoleId = @RoleId", connection);
                    command.Parameters.Add(new OleDbParameter("@RoleId", roleId));
                    int returnValue = command.ExecuteNonQuery();
                    command = new OleDbCommand("COMMIT TRANSACTION", connection);
                    command.ExecuteNonQuery();
                    fBeginTransCalled = false;

                    return (returnValue == 1);
                }
                catch (Exception e)
                {
                    if (fBeginTransCalled)
                    {
                        try
                        {
                            OleDbCommand command = new OleDbCommand("ROLLBACK TRANSACTION", connection);
                            command.ExecuteNonQuery();
                        }
                        catch { }
                    }
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    holder.Close();
                }
            }
            catch
            {
                throw;
            }
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override bool RoleExists(string roleName)
        {
            try
            {
                SecUtility.CheckParameter(ref roleName, true, true, true, 255, "roleName");
            }
            catch
            {
                return false;
            }
            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            try
            {
                try
                {
                    int appId = GetApplicationId(holder);
                    int roleId = GetRoleId(connection, appId, roleName);

                    return (roleId != 0);
                }
                catch (Exception e)
                {
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    holder.Close();
                }
            }
            catch
            {
                throw;
            }
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override void AddUsersToRoles(string[] usernames, string[] roleNames)
        {
            SecUtility.CheckArrayParameter(ref roleNames, true, true, true, 255, "roleNames");
            SecUtility.CheckArrayParameter(ref usernames, true, true, true, 255, "usernames");

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            bool fBeginTransCalled = false;
            try
            {
                try
                {
                    int appId = GetApplicationId(holder);
                    int[] userIds = new int[usernames.Length];
                    int[] roleIds = new int[roleNames.Length];

                    OleDbCommand command;

                    for (int iterR = 0; iterR < roleNames.Length; iterR++)
                    {
                        roleIds[iterR] = GetRoleId(connection, appId, roleNames[iterR]);
                        if (roleIds[iterR] == 0)
                        {
                            throw new ProviderException("Provider role not found: " + roleNames[iterR]);
                        }
                    }
                    for (int iterU = 0; iterU < usernames.Length; iterU++)
                    {
                        userIds[iterU] = AccessConnectionHelper.GetUserID(connection, appId, usernames[iterU], false);
                    }
                    command = new OleDbCommand("BEGIN TRANSACTION", connection);
                    command.ExecuteNonQuery();
                    fBeginTransCalled = true;

                    for (int iterU = 0; iterU < usernames.Length; iterU++)
                    {
                        if (userIds[iterU] == 0)
                            continue;
                        for (int iterR = 0; iterR < roleNames.Length; iterR++)
                        {
                            command = new OleDbCommand(@"SELECT UserId FROM aspnet_UsersInRoles WHERE UserId = @UserId AND RoleId = @RoleId",
                                                       connection);
                            command.Parameters.Add(new OleDbParameter("@UserId", userIds[iterU]));
                            command.Parameters.Add(new OleDbParameter("@RoleId", roleIds[iterR]));

                            object result = command.ExecuteScalar();
                            if (result != null && (result is int) && ((int)result) == userIds[iterU])
                            { // Exists!

                                throw new ProviderException("The user " + usernames[iterU] + " is already in role " + roleNames[iterR]);
                            }
                        }
                    }

                    for (int iterU = 0; iterU < usernames.Length; iterU++)
                    {
                        if (userIds[iterU] == 0)
                        {
                            userIds[iterU] = AccessConnectionHelper.GetUserID(connection, appId, usernames[iterU], true);
                        }
                        if (userIds[iterU] == 0)
                        {
                            throw new ProviderException("User not found: " + usernames[iterU]);
                        }
                    }
                    for (int iterU = 0; iterU < usernames.Length; iterU++)
                    {
                        for (int iterR = 0; iterR < roleNames.Length; iterR++)
                        {
                            command = new OleDbCommand(@"INSERT INTO aspnet_UsersInRoles (UserId, RoleId) VALUES(@UserId, @RoleId)",
                                                        connection);
                            command.Parameters.Add(new OleDbParameter("@UserId", userIds[iterU]));
                            command.Parameters.Add(new OleDbParameter("@RoleId", roleIds[iterR]));

                            if (command.ExecuteNonQuery() != 1)
                            {
                                throw new ProviderException("Unknown provider failure");
                            }
                        }
                    }
                    command = new OleDbCommand("COMMIT TRANSACTION", connection);
                    command.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    try
                    {
                        if (fBeginTransCalled)
                        {
                            OleDbCommand command = new OleDbCommand("ROLLBACK TRANSACTION", connection);
                            command.ExecuteNonQuery();
                        }
                    }
                    catch { }
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    holder.Close();
                }
            }
            catch
            {
                throw;
            }
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override void RemoveUsersFromRoles(string[] usernames, string[] roleNames)
        {
            SecUtility.CheckArrayParameter(ref roleNames, true, true, true, 255, "roleNames");
            SecUtility.CheckArrayParameter(ref usernames, true, true, true, 255, "usernames");

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            bool fBeginTransCalled = false;
            try
            {
                try
                {
                    int appId = GetApplicationId(holder);
                    int[] userIds = new int[usernames.Length];
                    int[] roleIds = new int[roleNames.Length];

                    OleDbCommand command;
                    command = new OleDbCommand("BEGIN TRANSACTION", connection);
                    command.ExecuteNonQuery();
                    fBeginTransCalled = true;


                    for (int iterU = 0; iterU < usernames.Length; iterU++)
                    {
                        userIds[iterU] = AccessConnectionHelper.GetUserID(connection, appId, usernames[iterU], false);
                        if (userIds[iterU] == 0)
                        {
                            throw new ProviderException("User not found: " + usernames[iterU]);
                        }
                    }
                    for (int iterR = 0; iterR < roleNames.Length; iterR++)
                    {
                        roleIds[iterR] = GetRoleId(connection, appId, roleNames[iterR]);
                        if (roleIds[iterR] == 0)
                        {
                            throw new ProviderException("Role not found: " + roleNames[iterR]);
                        }
                    }
                    for (int iterU = 0; iterU < usernames.Length; iterU++)
                    {
                        for (int iterR = 0; iterR < roleNames.Length; iterR++)
                        {
                            command = new OleDbCommand(@"SELECT UserId FROM aspnet_UsersInRoles WHERE UserId = @UserId AND RoleId = @RoleId",
                                                        connection);
                            command.Parameters.Add(new OleDbParameter("@UserId", userIds[iterU]));
                            command.Parameters.Add(new OleDbParameter("@RoleId", roleIds[iterR]));

                            object result = command.ExecuteScalar();
                            if (result == null || !(result is int) || ((int)result) != userIds[iterU])
                            { // doesn't exist!

                                throw new ProviderException("The user " + usernames[iterU] + " is already not in role " + roleNames[iterR]);
                            }
                        }
                    }

                    for (int iterU = 0; iterU < usernames.Length; iterU++)
                    {
                        for (int iterR = 0; iterR < roleNames.Length; iterR++)
                        {
                            command = new OleDbCommand(@"DELETE FROM aspnet_UsersInRoles WHERE UserId = @UserId AND RoleId = @RoleId",
                                                        connection);
                            command.Parameters.Add(new OleDbParameter("@UserId", userIds[iterU]));
                            command.Parameters.Add(new OleDbParameter("@RoleId", roleIds[iterR]));
                            if (command.ExecuteNonQuery() != 1)
                            {
                                throw new ProviderException("Unknown failure");
                            }
                        }
                    }
                    command = new OleDbCommand("COMMIT TRANSACTION", connection);
                    command.ExecuteNonQuery();
                }
                catch (Exception e)
                {
                    try
                    {
                        if (fBeginTransCalled)
                        {
                            OleDbCommand command = new OleDbCommand("ROLLBACK TRANSACTION", connection);
                            command.ExecuteNonQuery();
                        }
                    }
                    catch { }
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    holder.Close();
                }
            }
            catch
            {
                throw;
            }
        }


        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override string[] GetUsersInRole(string roleName)
        {
            SecUtility.CheckParameter(ref roleName, true, true, true, 255, "roleName");
            StringCollection sc = new StringCollection();
            String[] strReturn;
            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbDataReader reader = null;
            OleDbConnection connection = holder.Connection;
            try
            {
                try
                {
                    int appId = GetApplicationId(holder);
                    int roleId = GetRoleId(connection, appId, roleName);

                    OleDbCommand command;

                    if (roleId == 0)
                    {
                        throw new ProviderException("Role not found: " + roleName);
                    }

                    command = new OleDbCommand(@"SELECT UserName " +
                                               @"FROM aspnet_UsersInRoles ur, aspnet_Users u " +
                                               @"WHERE ur.RoleId = @RoleId AND ur.UserId = u.UserId " +
                                               @"ORDER BY UserName",
                                            connection);

                    command.Parameters.Add(new OleDbParameter("@RoleId", roleId));
                    reader = command.ExecuteReader(CommandBehavior.SequentialAccess);
                    while (reader.Read())
                        sc.Add(reader.GetString(0));

                }
                catch (Exception e)
                {
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    if (reader != null)
                        reader.Close();
                    holder.Close();
                }
            }
            catch
            {
                throw;
            }

            strReturn = new String[sc.Count];
            sc.CopyTo(strReturn, 0);
            return strReturn;
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        public override string[] FindUsersInRole(string roleName, string usernameToMatch)
        {
            SecUtility.CheckParameter(ref roleName, true, true, true, 255, "roleName");
            SecUtility.CheckParameter(ref usernameToMatch, true, true, false, 255, "usernameToMatch");

            StringCollection sc = new StringCollection();

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbDataReader reader = null;
            OleDbConnection connection = holder.Connection;
            try
            {
                try
                {
                    int appId = GetApplicationId(holder);
                    int roleId = GetRoleId(connection, appId, roleName);

                    OleDbCommand command;

                    if (roleId == 0)
                    {
                        throw new ProviderException("Role not found " + roleName);
                    }

                    command = new OleDbCommand(@"SELECT UserName " +
                                               @"FROM aspnet_UsersInRoles ur, aspnet_Users u " +
                                               @"WHERE ur.RoleId = @RoleId AND ur.UserId = u.UserId AND u.UserName LIKE @UserNameToMatch " +
                                               @"ORDER BY UserName", connection);

                    command.Parameters.Add(new OleDbParameter("@RoleId", roleId));
                    command.Parameters.Add(new OleDbParameter("@UserNameToMatch", usernameToMatch));
                    reader = command.ExecuteReader(CommandBehavior.SequentialAccess);
                    while (reader.Read())
                        sc.Add((string)reader.GetString(0));
                }
                catch (Exception e)
                {
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    if (reader != null)
                        reader.Close();
                    holder.Close();
                }
            }
            catch
            {
                throw;
            }
            string[] allUsers = new string[sc.Count];
            sc.CopyTo(allUsers, 0);
            return allUsers;
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override string[] GetAllRoles()
        {
            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            OleDbDataReader reader = null;
            try
            {
                try
                {
                    int appId = GetApplicationId(holder);
                    OleDbCommand command;
                    StringCollection sc = new StringCollection();
                    String[] strReturn = null;

                    command = new OleDbCommand(@"SELECT RoleName FROM aspnet_Roles WHERE ApplicationId = @AppId ORDER BY RoleName", connection);
                    command.Parameters.Add(new OleDbParameter("@AppId", appId));
                    reader = command.ExecuteReader(CommandBehavior.SequentialAccess);
                    while (reader.Read())
                        sc.Add(reader.GetString(0));
                    strReturn = new String[sc.Count];
                    sc.CopyTo(strReturn, 0);
                    return strReturn;
                }
                catch (Exception e)
                {
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    if (reader != null)
                        reader.Close();
                    holder.Close();
                }
            }
            catch
            {
                throw;
            }
        }


        public override string ApplicationName
        {
            get { return _AppName; }
            set
            {
                if (_AppName != value)
                {
                    _ApplicationId = 0;
                    _AppName = value;
                }
            }
        }
        /////////////////////////////////////////////////////////////////////////////
        private int GetRoleId(OleDbConnection connection, int appId, string roleName)
        {
            object result;
            OleDbCommand command;

            command = new OleDbCommand(@"SELECT RoleId FROM aspnet_Roles WHERE ApplicationId = @AppId AND RoleName = @RoleName",
                                       connection);
            command.Parameters.Add(new OleDbParameter("@AppId", appId));
            command.Parameters.Add(new OleDbParameter("@RoleName", roleName));
            result = command.ExecuteScalar();
            if (result == null || !(result is int) || ((int)result) == 0)
            {
                return 0;
            }
            else
            {
                return (int)result;
            }
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////

        private int GetApplicationId(AccessConnectionHolder holder)
        {
            if (_ApplicationId != 0 && holder.CreateDate < _ApplicationIDCacheDate) // Already cached?
                return _ApplicationId;
            string appName = _AppName;
            if (appName.Length > 255)
                appName = appName.Substring(0, 255);
            _ApplicationId = AccessConnectionHelper.GetApplicationID(holder.Connection, appName, true);
            _ApplicationIDCacheDate = DateTime.Now;
            if (_ApplicationId != 0)
                return _ApplicationId;
            throw new ProviderException("Provider Error");
        }

    }

}
