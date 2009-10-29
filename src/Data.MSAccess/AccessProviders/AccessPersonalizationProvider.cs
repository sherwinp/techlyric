//------------------------------------------------------------------------------
// <copyright file="AccessPersonalizationProvider.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

namespace AccessProviders
{

    using System;
    using System.Collections;
    using System.Collections.Specialized;
    using System.ComponentModel;
    using System.Configuration.Provider;
    using System.Globalization;
    using System.Data;
    using System.Data.OleDb;
    using System.Security.Permissions;
    using System.Web.UI.WebControls.WebParts;
    using System.Web.Security;
    using System.Web.DataAccess;
    using System.Web.Util;

    /// <devdoc>
    /// The provider used to access the personalization store for WebPart pages from an AccessProviders
    /// database.
    /// </devdoc>
    public sealed class AccessPersonalizationProvider : PersonalizationProvider
    {

        private const int MaxStringLength = 255;

        private string _applicationName;
        private int _applicationID;
        private DateTime _applicationIDCacheDate;
        private string _databaseFileName;

        /// <devdoc>
        /// Initializes an instance of AccessPersonalizationProvider.
        /// </devdoc>
        public AccessPersonalizationProvider()
        {
        }

        public override string ApplicationName
        {
            get
            {
                if (String.IsNullOrEmpty(_applicationName))
                {
                    _applicationName = SecUtility.GetDefaultAppName();
                }
                return _applicationName;
            }
            set
            {
                if (value != null && value.Length > MaxStringLength)
                {
                    throw new ProviderException("ApplicationName exceeded max length of " + MaxStringLength);
                }
                _applicationName = value;
            }
        }

        private OleDbParameter CreateDateTimeOleDbParameter(string parameterName, DateTime dt)
        {
            OleDbParameter p = new OleDbParameter(parameterName, OleDbType.DBTimeStamp);
            p.Direction = ParameterDirection.Input;
            p.Value = AccessConnectionHelper.RoundToSeconds(dt);
            return p;
        }

        private byte[] Deserialize(string data)
        {
            if (String.IsNullOrEmpty(data))
            {
                return null;
            }
            return Convert.FromBase64String(data);
        }

        private int GetApplicationID(AccessConnectionHolder holder)
        {
            if (_applicationID != 0 && holder.CreateDate < _applicationIDCacheDate)
            {
                return _applicationID;
            }

            string appName = ApplicationName;
            if (appName.Length > MaxStringLength)
            {
                appName = appName.Substring(0, MaxStringLength);
            }

            _applicationID = AccessConnectionHelper.GetApplicationID(holder.Connection, appName, true);
            _applicationIDCacheDate = DateTime.Now;

            if (_applicationID == 0)
            {
                throw new ProviderException("Failed to get ApplicationID");
            }

            return _applicationID;
        }

        private PersonalizationStateInfoCollection FindSharedState(string path,
                                                                   int pageIndex,
                                                                   int pageSize,
                                                                   out int totalRecords)
        {
            const string findSharedState =
                "SELECT Paths.Path, AllUsers.LastUpdatedDate, LEN(AllUsers.PageSettings)" +
                " FROM aspnet_PagePersonalizationAllUsers AllUsers, aspnet_Paths Paths" +
                " WHERE AllUsers.PathId = Paths.PathId AND Paths.ApplicationId = @ApplicationId";
            const string orderBy = " ORDER BY Paths.Path ASC";
            const string findUserState =
                "SELECT SUM(LEN(PerUser.PageSettings)), COUNT(*)" +
                " FROM aspnet_PagePersonalizationPerUser PerUser, aspnet_Paths Paths" +
                " WHERE PerUser.PathId = Paths.PathId" +
                " AND Paths.ApplicationId = @ApplicationId" +
                " AND Paths.Path LIKE @Path";

            AccessConnectionHolder connectionHolder = null;
            OleDbConnection connection = null;
            OleDbDataReader reader = null;
            totalRecords = 0;


            try
            {
                try
                {
                    connectionHolder = GetConnectionHolder();
                    connection = connectionHolder.Connection;
                    OleDbCommand command = new OleDbCommand(findSharedState, connection);
                    OleDbParameterCollection parameters = command.Parameters;
                    OleDbParameter parameter;

                    int appId = GetApplicationID(connectionHolder);
                    parameters.AddWithValue("ApplicationId", appId);

                    if (path != null)
                    {
                        command.CommandText += " AND Paths.Path LIKE @Path";
                        parameter = parameters.Add("Path", OleDbType.WChar);
                        parameter.Value = path;
                    }

                    command.CommandText += orderBy;
                    reader = command.ExecuteReader(CommandBehavior.SequentialAccess);
                    PersonalizationStateInfoCollection stateInfoCollection = new PersonalizationStateInfoCollection();
                    long recordCount = 0;
                    long lBound = pageIndex * pageSize;
                    long uBound = lBound + pageSize;

                    while (reader.Read())
                    {
                        recordCount++;
                        if (recordCount <= lBound || recordCount > uBound)
                        {
                            continue;
                        }

                        string returnedPath = reader.GetString(0);
                        DateTime lastUpdatedDate = reader.GetDateTime(1);
                        int size = reader.GetInt32(2);

                        // Create temp info since we need to retrieve the corresponding personalization size and count later
                        stateInfoCollection.Add(new SharedPersonalizationStateInfo(returnedPath, lastUpdatedDate, size, -1, -1));
                    }
                    totalRecords = (int)recordCount;

                    // We need to close the reader in order to make other queries
                    reader.Close();
                    command = new OleDbCommand(findUserState, connection);
                    parameters = command.Parameters;

                    parameters.AddWithValue("ApplicationId", appId);
                    parameter = parameters.Add("Path", OleDbType.WChar);
                    PersonalizationStateInfoCollection sharedStateInfoCollection = new PersonalizationStateInfoCollection();

                    foreach (PersonalizationStateInfo stateInfo in stateInfoCollection)
                    {
                        parameter.Value = stateInfo.Path;

                        reader = command.ExecuteReader(CommandBehavior.SequentialAccess);
                        reader.Read();
                        int sizeOfPersonalizations = Convert.ToInt32(reader.GetValue(0), CultureInfo.InvariantCulture);
                        int countOfPersonalizations = reader.GetInt32(1);
                        reader.Close();
                        sharedStateInfoCollection.Add(new SharedPersonalizationStateInfo(
                                                            stateInfo.Path, stateInfo.LastUpdatedDate,
                                                            stateInfo.Size, sizeOfPersonalizations, countOfPersonalizations));
                    }

                    return sharedStateInfoCollection;
                }
                finally
                {
                    if (connectionHolder != null)
                    {
                        connectionHolder.Close();
                        connectionHolder = null;
                    }

                    if (reader != null)
                    {
                        reader.Close();
                    }
                }
            }
            catch
            {
                throw;
            }
        }

        public override PersonalizationStateInfoCollection FindState(PersonalizationScope scope,
                                                                     PersonalizationStateQuery query,
                                                                     int pageIndex,
                                                                     int pageSize,
                                                                     out int totalRecords)
        {
            PersonalizationProviderHelper.CheckPersonalizationScope(scope);
            PersonalizationProviderHelper.CheckPageIndexAndSize(pageIndex, pageSize);

            if (scope == PersonalizationScope.Shared)
            {
                string pathToMatch = null;
                if (query != null)
                {
                    pathToMatch = PersonalizationProviderHelper.CheckAndTrimString(query.PathToMatch, "query.PathToMatch", false, MaxStringLength);
                }
                return FindSharedState(pathToMatch, pageIndex, pageSize, out totalRecords);
            }
            else
            {
                string pathToMatch = null;
                DateTime inactiveSinceDate = DateTime.MinValue;
                string usernameToMatch = null;
                if (query != null)
                {
                    pathToMatch = PersonalizationProviderHelper.CheckAndTrimString(query.PathToMatch, "query.PathToMatch", false, MaxStringLength);
                    inactiveSinceDate = query.UserInactiveSinceDate;
                    usernameToMatch = PersonalizationProviderHelper.CheckAndTrimString(
                                            query.UsernameToMatch, "query.UsernameToMatch", false, MaxStringLength);
                }

                return FindUserState(pathToMatch, inactiveSinceDate, usernameToMatch,
                                     pageIndex, pageSize, out totalRecords);
            }
        }

        private PersonalizationStateInfoCollection FindUserState(string path,
                                                                 DateTime inactiveSinceDate,
                                                                 string username,
                                                                 int pageIndex,
                                                                 int pageSize,
                                                                 out int totalRecords)
        {
            const string findUserState =
                "SELECT Paths.Path, PerUser.LastUpdatedDate, LEN(PerUser.PageSettings), Users.UserName, Users.LastActivityDate" +
                " FROM aspnet_PagePersonalizationPerUser PerUser, aspnet_Users Users, aspnet_Paths Paths" +
                " WHERE PerUser.UserId = Users.UserId AND PerUser.PathId = Paths.PathId" +
                " AND Paths.ApplicationId = @ApplicationId";
            const string orderBy = " ORDER BY Paths.Path ASC, Users.UserName ASC";

            AccessConnectionHolder connectionHolder = null;
            OleDbConnection connection = null;
            OleDbDataReader reader = null;
            totalRecords = 0;


            try
            {
                try
                {
                    OleDbParameter parameter;
                    connectionHolder = GetConnectionHolder();
                    connection = connectionHolder.Connection;
                    OleDbCommand command = new OleDbCommand();
                    command.Connection = connection;
                    OleDbParameterCollection parameters = command.Parameters;

                    int appId = GetApplicationID(connectionHolder);
                    parameters.AddWithValue("ApplicationId", appId);

                    command.CommandText = findUserState;
                    if (inactiveSinceDate != DateTime.MinValue)
                    {
                        command.CommandText += " AND Users.LastActivityDate <= @InactiveSinceDate";

                        // Note: OleDb provider does not handle datetime that has non-
                        // zero millisecond, so it needs to be rounded up.
                        parameter = parameters.Add("InactiveSinceDate", OleDbType.DBTimeStamp);
                        parameter.Value = new DateTime(inactiveSinceDate.Year, inactiveSinceDate.Month, inactiveSinceDate.Day,
                                                       inactiveSinceDate.Hour, inactiveSinceDate.Minute, inactiveSinceDate.Second);
                    }

                    if (path != null)
                    {
                        command.CommandText += " AND Paths.Path LIKE @Path";
                        parameter = parameters.Add("Path", OleDbType.WChar);
                        parameter.Value = path;
                    }

                    if (username != null)
                    {
                        command.CommandText += " AND Users.UserName LIKE @UserName";
                        parameter = parameters.Add("UserName", OleDbType.WChar);
                        parameter.Value = username;
                    }

                    command.CommandText += orderBy;
                    reader = command.ExecuteReader(CommandBehavior.SequentialAccess);
                    PersonalizationStateInfoCollection stateInfoCollection = new PersonalizationStateInfoCollection();
                    long recordCount = 0;
                    long lBound = pageIndex * pageSize;
                    long uBound = lBound + pageSize;

                    while (reader.Read())
                    {
                        recordCount++;
                        if (recordCount <= lBound || recordCount > uBound)
                        {
                            continue;
                        }

                        string returnedPath = reader.GetString(0);
                        DateTime lastUpdatedDate = reader.GetDateTime(1);
                        int size = reader.GetInt32(2);
                        string returnedUsername = reader.GetString(3);
                        DateTime lastActivityDate = reader.GetDateTime(4);
                        stateInfoCollection.Add(new UserPersonalizationStateInfo(
                                                        returnedPath, lastUpdatedDate,
                                                        size, returnedUsername, lastActivityDate));
                    }
                    totalRecords = (int)recordCount;
                    return stateInfoCollection;
                }
                finally
                {
                    if (connectionHolder != null)
                    {
                        connectionHolder.Close();
                        connectionHolder = null;
                    }

                    if (reader != null)
                    {
                        reader.Close();
                    }
                }
            }
            catch
            {
                throw;
            }
        }

        private AccessConnectionHolder GetConnectionHolder()
        {
            OleDbConnection connection = null;
            AccessConnectionHolder connectionHolder = AccessConnectionHelper.GetConnection(_databaseFileName, true);

            if (connectionHolder != null)
            {
                connection = connectionHolder.Connection;
            }
            if (connection == null)
            {
                throw new ProviderException("PersonalizationProvider cannot access: " + Name);
            }

            return connectionHolder;
        }

        private int GetCountOfSharedState(string path)
        {
            string getSharedStateCount =
                "SELECT COUNT(*)" +
                " FROM aspnet_PagePersonalizationAllUsers AllUsers, aspnet_Paths Paths" +
                " WHERE AllUsers.PathId = Paths.PathId AND Paths.ApplicationId = @ApplicationId";

            AccessConnectionHolder connectionHolder = null;
            OleDbConnection connection = null;
            int count = 0;


            try
            {
                try
                {
                    connectionHolder = GetConnectionHolder();
                    connection = connectionHolder.Connection;

                    OleDbCommand command = new OleDbCommand();
                    command.Connection = connection;
                    OleDbParameterCollection parameters = command.Parameters;

                    int appId = GetApplicationID(connectionHolder);
                    parameters.AddWithValue("ApplicationId", appId);

                    if (path != null)
                    {
                        getSharedStateCount += " AND Paths.Path LIKE @Path";
                        OleDbParameter parameter = parameters.Add("Path", OleDbType.WChar);
                        parameter.Value = path;
                    }
                    command.CommandText = getSharedStateCount;

                    object result = command.ExecuteScalar();
                    if ((result != null) && (result is Int32))
                    {
                        count = (Int32)result;
                    }
                }
                finally
                {
                    if (connectionHolder != null)
                    {
                        connectionHolder.Close();
                        connectionHolder = null;
                    }
                }
            }
            catch
            {
                throw;
            }

            return count;
        }

        public override int GetCountOfState(PersonalizationScope scope, PersonalizationStateQuery query)
        {
            PersonalizationProviderHelper.CheckPersonalizationScope(scope);
            if (scope == PersonalizationScope.Shared)
            {
                string pathToMatch = null;
                if (query != null)
                {
                    pathToMatch = PersonalizationProviderHelper.CheckAndTrimString(query.PathToMatch, "query.PathToMatch", false, MaxStringLength);
                }
                return GetCountOfSharedState(pathToMatch);
            }
            else
            {
                string pathToMatch = null;
                DateTime userInactiveSinceDate = DateTime.MinValue;
                string usernameToMatch = null;
                if (query != null)
                {
                    pathToMatch = PersonalizationProviderHelper.CheckAndTrimString(query.PathToMatch, "query.PathToMatch", false, MaxStringLength);
                    userInactiveSinceDate = query.UserInactiveSinceDate;
                    usernameToMatch = PersonalizationProviderHelper.CheckAndTrimString(
                                            query.UsernameToMatch, "query.UsernameToMatch", false, MaxStringLength);
                }
                return GetCountOfUserState(pathToMatch, userInactiveSinceDate, usernameToMatch);
            }
        }

        private int GetCountOfUserState(string path, DateTime inactiveSinceDate, string username)
        {
            string getUserStateCount =
                "SELECT COUNT(*)" +
                " FROM aspnet_PagePersonalizationPerUser PerUser, aspnet_Users Users, aspnet_Paths Paths" +
                " WHERE PerUser.UserId = Users.UserId AND PerUser.PathId = Paths.PathId" +
                " AND Paths.ApplicationId = @ApplicationId";

            AccessConnectionHolder connectionHolder = null;
            OleDbConnection connection = null;
            int count = 0;


            try
            {
                try
                {
                    OleDbParameter parameter;
                    connectionHolder = GetConnectionHolder();
                    connection = connectionHolder.Connection;
                    OleDbCommand command = new OleDbCommand();
                    command.Connection = connection;
                    OleDbParameterCollection parameters = command.Parameters;

                    int appId = GetApplicationID(connectionHolder);
                    parameter = parameters.AddWithValue("ApplicationId", appId);

                    if (path != null)
                    {
                        getUserStateCount += " AND Paths.Path LIKE @Path";
                        parameter = parameters.Add("Path", OleDbType.WChar);
                        parameter.Value = path;
                    }

                    if (username != null)
                    {
                        getUserStateCount += " AND Users.UserName LIKE @UserName";
                        parameter = parameters.Add("UserName", OleDbType.WChar);
                        parameter.Value = username;
                    }

                    if (inactiveSinceDate != DateTime.MinValue)
                    {
                        getUserStateCount += " AND Users.LastActivityDate <= @InactiveSinceDate";

                        // Note: OleDb provider does not handle datetime that has non-
                        // zero millisecond, so it needs to be rounded up.
                        parameter = parameters.Add("InactiveSinceDate", OleDbType.DBTimeStamp);
                        parameter.Value = new DateTime(inactiveSinceDate.Year, inactiveSinceDate.Month, inactiveSinceDate.Day,
                                                       inactiveSinceDate.Hour, inactiveSinceDate.Minute, inactiveSinceDate.Second);
                    }

                    command.CommandText = getUserStateCount;

                    object result = command.ExecuteScalar();
                    if ((result != null) && (result is Int32))
                    {
                        count = (Int32)result;
                    }
                }
                finally
                {
                    if (connectionHolder != null)
                    {
                        connectionHolder.Close();
                        connectionHolder = null;
                    }
                }
            }
            catch
            {
                throw;
            }

            return count;
        }

        public override void Initialize(string name, NameValueCollection configSettings)
        {
            base.Initialize(name, configSettings);

            // If not available, the default value is set in the get accessor of ApplicationName
            _applicationName = configSettings["applicationName"];
            if (_applicationName != null)
            {
                configSettings.Remove("applicationName");

                if (_applicationName.Length > MaxStringLength)
                {
                    throw new ProviderException("ApplicationName exceeded max length of " + MaxStringLength);
                }
            }

            string connectionStringName = configSettings["connectionStringName"];

            if (String.IsNullOrEmpty(connectionStringName))
            {
                throw new ProviderException("No connection string specified.");
            }
            configSettings.Remove("connectionStringName");

            string databaseFileName = AccessConnectionHelper.GetFileNameFromConnectionName(connectionStringName, true);
            if (String.IsNullOrEmpty(databaseFileName))
            {
                throw new ProviderException("Bad connection string: " + connectionStringName);
            }

            _databaseFileName = databaseFileName;
            if (configSettings.Count > 0)
            {
                string invalidAttributeName = configSettings.GetKey(0);

                throw new ProviderException("Unknown attribute: " + invalidAttributeName + name);
            }
        }

        private string LoadPersonalizationBlob(OleDbConnection connection, int pathID)
        {
            OleDbCommand lookupCommand = new OleDbCommand("SELECT PageSettings FROM aspnet_PagePersonalizationAllUsers WHERE PathId = @PathId", connection);
            lookupCommand.Parameters.Add(new OleDbParameter("@PathId", pathID));

            object lookupResult = lookupCommand.ExecuteScalar();
            if ((lookupResult != null) && (lookupResult is string))
            {
                return (string)lookupResult;
            }

            return null;
        }

        private string LoadPersonalizationBlob(OleDbConnection connection, int pathID, int userID)
        {
            OleDbCommand updateCommand = new OleDbCommand(@"UPDATE  aspnet_Users " +
                                                          @"SET     LastActivityDate = @LastActivityDate " +
                                                          @"WHERE   UserId = @UserId", connection);
            updateCommand.Parameters.Add(CreateDateTimeOleDbParameter("@LastActivityDate", DateTime.Now));
            updateCommand.Parameters.Add(new OleDbParameter("@UserId", userID));
            updateCommand.ExecuteNonQuery();

            OleDbCommand lookupCommand = new OleDbCommand("SELECT PageSettings FROM aspnet_PagePersonalizationPerUser WHERE PathId = @PathId AND UserId = @UserId", connection);
            lookupCommand.Parameters.Add(new OleDbParameter("@PathId", pathID));
            lookupCommand.Parameters.Add(new OleDbParameter("@UserId", userID));

            object lookupResult = lookupCommand.ExecuteScalar();
            if ((lookupResult != null) && (lookupResult is string))
            {
                return (string)lookupResult;
            }

            return null;
        }

        protected override void LoadPersonalizationBlobs(WebPartManager webPartManager, string path, string userName, ref byte[] sharedDataBlob, ref byte[] userDataBlob)
        {
            sharedDataBlob = null;
            userDataBlob = null;

            AccessConnectionHolder connectionHolder = null;
            OleDbConnection connection = null;


            try
            {
                try
                {
                    connectionHolder = GetConnectionHolder();
                    connection = connectionHolder.Connection;

                    int applicationID = GetApplicationID(connectionHolder);
                    if (applicationID != 0)
                    {
                        int pathID = AccessConnectionHelper.GetPathID(connection, applicationID, path);
                        if (pathID != 0)
                        {
                            string sharedDataValue = LoadPersonalizationBlob(connection, pathID);
                            sharedDataBlob = Deserialize(sharedDataValue);

                            if (userName != null)
                            {
                                int userID = AccessConnectionHelper.GetUserID(connection, applicationID, userName);
                                if (userID != 0)
                                {
                                    string userDataValue = LoadPersonalizationBlob(connection, pathID, userID);
                                    userDataBlob = Deserialize(userDataValue);
                                }
                            }
                        }
                    }
                }
                finally
                {
                    if (connectionHolder != null)
                    {
                        connectionHolder.Close();
                        connectionHolder = null;
                    }
                }
            }
            catch
            {
                throw;
            }
        }

        private void ResetPersonalizationBlob(OleDbConnection connection, int pathID)
        {
            OleDbCommand lookupCommand = new OleDbCommand("DELETE FROM aspnet_PagePersonalizationAllUsers WHERE PathId = @PathId", connection);

            lookupCommand.Parameters.Add(new OleDbParameter("@PathId", pathID));
            lookupCommand.ExecuteNonQuery();
        }

        private void ResetPersonalizationBlob(OleDbConnection connection, int pathID, int userID)
        {
            OleDbCommand lookupCommand = new OleDbCommand("DELETE FROM aspnet_PagePersonalizationPerUser WHERE PathId = @PathId AND UserId = @UserId", connection);

            lookupCommand.Parameters.Add(new OleDbParameter("@PathId", pathID));
            lookupCommand.Parameters.Add(new OleDbParameter("@UserId", userID));
            lookupCommand.ExecuteNonQuery();
        }

        protected override void ResetPersonalizationBlob(WebPartManager webPartManager, string path, string userName)
        {
            AccessConnectionHolder connectionHolder = null;
            OleDbConnection connection = null;


            try
            {
                try
                {
                    connectionHolder = GetConnectionHolder();
                    connection = connectionHolder.Connection;

                    int applicationID = GetApplicationID(connectionHolder);
                    if (applicationID != 0)
                    {
                        int pathID = AccessConnectionHelper.GetPathID(connection, applicationID, path);

                        if (pathID != 0)
                        {
                            if (String.IsNullOrEmpty(userName))
                            {
                                ResetPersonalizationBlob(connection, pathID);
                            }
                            else
                            {
                                int userID = AccessConnectionHelper.GetUserID(connection, applicationID, userName);
                                if (userID != 0)
                                {
                                    ResetPersonalizationBlob(connection, pathID, userID);
                                }
                            }
                        }
                    }
                }
                finally
                {
                    if (connectionHolder != null)
                    {
                        connectionHolder.Close();
                        connectionHolder = null;
                    }
                }
            }
            catch
            {
                throw;
            }
        }

        private int ResetAllState(string getStateCountQuery, string deleteStateQuery)
        {
            AccessConnectionHolder connectionHolder = null;
            OleDbConnection connection = null;
            int count = 0;


            try
            {
                try
                {
                    connectionHolder = GetConnectionHolder();
                    connection = connectionHolder.Connection;

                    // Get the count of records that would be deleted
                    OleDbCommand command = new OleDbCommand(getStateCountQuery, connection);
                    object lookupResult = command.ExecuteScalar();
                    if ((lookupResult != null) && (lookupResult is Int32))
                    {
                        count = (Int32)lookupResult;
                    }

                    // Do the actual deletion
                    command.CommandText = deleteStateQuery;
                    command.ExecuteNonQuery();
                }
                finally
                {
                    if (connectionHolder != null)
                    {
                        connectionHolder.Close();
                        connectionHolder = null;
                    }
                }
            }
            catch
            {
                throw;
            }

            return count;
        }

        private int ResetSharedState(string[] paths)
        {
            if (paths == null)
            {
                const string deleteAllSharedState = "DELETE FROM aspnet_PagePersonalizationAllUsers";
                const string getAllSharedStateCount = "SELECT COUNT(*) FROM aspnet_PagePersonalizationAllUsers";
                return ResetAllState(getAllSharedStateCount, deleteAllSharedState);
            }
            else
            {
                return ResetStatePerPaths("aspnet_PagePersonalizationAllUsers", paths);
            }
        }

        public override int ResetUserState(string path, DateTime userInactiveSinceDate)
        {
            path = PersonalizationProviderHelper.CheckAndTrimString(path, "path", false, MaxStringLength);

            AccessConnectionHolder connectionHolder = null;
            OleDbConnection connection = null;
            int count = 0;


            try
            {
                try
                {
                    connectionHolder = GetConnectionHolder();
                    connection = connectionHolder.Connection;

                    // Special note: OleDbProvider requires the parameters to be added
                    // in the same order as appearing in the query text.

                    string getDeleteUserStateCount =
                        "SELECT COUNT(*)" +
                        " FROM aspnet_PagePersonalizationPerUser PerUser, aspnet_Users Users, aspnet_Paths Paths" +
                        " WHERE PerUser.UserId = Users.UserId AND PerUser.PathId = Paths.PathId" +
                        " AND Paths.ApplicationId = @ApplicationId" +
                        " AND Users.LastActivityDate <= @InactiveSinceDate";

                    string deleteUserState =
                        "DELETE FROM aspnet_PagePersonalizationPerUser" +
                        " WHERE Id IN (SELECT PerUser.Id " +
                                     " FROM aspnet_PagePersonalizationPerUser PerUser, aspnet_Users Users, aspnet_Paths Paths" +
                                     " WHERE PerUser.UserId = Users.UserId AND PerUser.PathId = Paths.PathId" +
                                     " AND Paths.ApplicationId = @ApplicationId" +
                                     " AND Users.LastActivityDate <= @InactiveSinceDate";

                    // Get the count of records that would be deleted
                    OleDbCommand command = new OleDbCommand();
                    command.Connection = connection;
                    OleDbParameterCollection parameters = command.Parameters;
                    OleDbParameter parameter;

                    int appId = GetApplicationID(connectionHolder);
                    parameters.AddWithValue("ApplicationId", appId);

                    // Note: OleDb provider does not handle datetime that has non-
                    // zero millisecond, so it needs to be rounded up.
                    parameter = parameters.Add("InactiveSinceDate", OleDbType.DBTimeStamp);
                    parameter.Value = new DateTime(userInactiveSinceDate.Year, userInactiveSinceDate.Month, userInactiveSinceDate.Day,
                                                   userInactiveSinceDate.Hour, userInactiveSinceDate.Minute, userInactiveSinceDate.Second);

                    if (path != null)
                    {
                        const string pathParamQueryText = " AND Paths.Path = @Path";
                        getDeleteUserStateCount += pathParamQueryText;
                        deleteUserState += pathParamQueryText;
                        parameters.AddWithValue("Path", path);
                    }
                    deleteUserState += ")";

                    command.CommandText = getDeleteUserStateCount;

                    object lookupResult = command.ExecuteScalar();
                    if ((lookupResult != null) && (lookupResult is Int32))
                    {
                        count = (Int32)lookupResult;
                        if (count > 0)
                        {
                            // Do the actual deletion
                            command.CommandText = deleteUserState;
                            command.ExecuteNonQuery();
                        }
                    }
                }
                finally
                {
                    if (connectionHolder != null)
                    {
                        connectionHolder.Close();
                        connectionHolder = null;
                    }
                }
            }
            catch
            {
                throw;
            }

            return count;
        }

        public override int ResetState(PersonalizationScope scope, string[] paths, string[] usernames)
        {
            PersonalizationProviderHelper.CheckPersonalizationScope(scope);
            paths = PersonalizationProviderHelper.CheckAndTrimNonEmptyStringEntries(paths, "paths", false, false, MaxStringLength);
            usernames = PersonalizationProviderHelper.CheckAndTrimNonEmptyStringEntries(usernames, "usernames", false, true, MaxStringLength);

            if (scope == PersonalizationScope.Shared)
            {
                PersonalizationProviderHelper.CheckUsernamesInSharedScope(usernames);
                return ResetSharedState(paths);
            }
            else
            {
                PersonalizationProviderHelper.CheckOnlyOnePathWithUsers(paths, usernames);
                return ResetUserState(paths, usernames);
            }
        }

        private int ResetUserState(string[] paths, string[] usernames)
        {
            int count = 0;
            bool hasPaths = !(paths == null || paths.Length == 0);
            bool hasUsernames = !(usernames == null || usernames.Length == 0);

            if (!hasPaths && !hasUsernames)
            {
                const string deleteAllUserState = "DELETE FROM aspnet_PagePersonalizationPerUser";
                const string getAllUserStateCount = "SELECT COUNT(*) FROM aspnet_PagePersonalizationPerUser";
                count = ResetAllState(getAllUserStateCount, deleteAllUserState);
            }
            else if (!hasUsernames)
            {
                count = ResetStatePerPaths("aspnet_PagePersonalizationPerUser", paths);
            }
            else
            {
                string path = (paths != null) ? paths[0] : null;
                count = ResetUserStatePerUsers(path, usernames);
            }

            return count;
        }

        private int ResetStatePerPaths(string tableName, string[] paths)
        {
            if (paths == null || paths.Length == 0)
            {
                return 0;
            }

            int count = 0;
            AccessConnectionHolder connectionHolder = null;
            OleDbConnection connection = null;
            bool beginTransCalled = false;

            try
            {
                try
                {
                    connectionHolder = GetConnectionHolder();
                    connection = connectionHolder.Connection;

                    int applicationID = GetApplicationID(connectionHolder);
                    if (applicationID != 0)
                    {
                        string fromAndWhereClause = " FROM " + tableName + " WHERE PathId = @PathId";
                        string selectCommandText = "SELECT COUNT(*)" + fromAndWhereClause;
                        string deleteCommandText = "DELETE" + fromAndWhereClause;
                        OleDbCommand command = new OleDbCommand(null, connection);
                        OleDbParameter pathParam = command.Parameters.Add(new OleDbParameter("@PathId", OleDbType.Integer));

                        OleDbCommand transCommand = new OleDbCommand("BEGIN TRANSACTION", connection);
                        transCommand.ExecuteNonQuery();
                        beginTransCalled = true;

                        foreach (string path in paths)
                        {
                            command.CommandText = selectCommandText;
                            pathParam.Value = AccessConnectionHelper.GetPathID(connection, applicationID, path);
                            int numOfRecords = (int)command.ExecuteScalar();
                            if (numOfRecords > 0)
                            {
                                command.CommandText = deleteCommandText;
                                command.ExecuteNonQuery();
                                count += numOfRecords;
                            }
                        }

                        transCommand.CommandText = "COMMIT TRANSACTION";
                        transCommand.ExecuteNonQuery();
                    }
                }
                catch
                {
                    try
                    {
                        if (beginTransCalled)
                        {
                            OleDbCommand rollbackCommand = new OleDbCommand("ROLLBACK TRANSACTION", connection);
                            rollbackCommand.ExecuteNonQuery();
                        }
                    }
                    catch
                    {
                    }
                    throw;
                }
                finally
                {
                    if (connectionHolder != null)
                    {
                        connectionHolder.Close();
                        connectionHolder = null;
                    }
                }
            }
            catch
            {
                throw;
            }

            return count;
        }

        private int ResetUserStatePerUsers(string path, string[] usernames)
        {
            int count = 0;
            AccessConnectionHolder connectionHolder = null;
            OleDbConnection connection = null;
            bool beginTransCalled = false;

            try
            {
                try
                {
                    connectionHolder = GetConnectionHolder();
                    connection = connectionHolder.Connection;

                    int applicationID = GetApplicationID(connectionHolder);
                    if (applicationID != 0)
                    {
                        OleDbCommand command = new OleDbCommand(null, connection);
                        OleDbParameter userIdParam = command.Parameters.Add(new OleDbParameter("@UserId", OleDbType.Integer));
                        string fromAndWhereClause = " FROM aspnet_PagePersonalizationPerUser WHERE UserId = @UserId";
                        if (!String.IsNullOrEmpty(path))
                        {
                            int pathId = AccessConnectionHelper.GetPathID(connection, applicationID, path);
                            fromAndWhereClause += " AND PathId = @PathId";
                            command.Parameters.Add(new OleDbParameter("@PathId", pathId));
                        }

                        string selectCommandText = "SELECT COUNT(*)" + fromAndWhereClause;
                        string deleteCommandText = "DELETE" + fromAndWhereClause;

                        OleDbCommand transCommand = new OleDbCommand("BEGIN TRANSACTION", connection);
                        transCommand.ExecuteNonQuery();
                        beginTransCalled = true;

                        foreach (string username in usernames)
                        {
                            command.CommandText = selectCommandText;
                            userIdParam.Value = AccessConnectionHelper.GetUserID(connection, applicationID, username);
                            int numOfRecords = (int)command.ExecuteScalar();
                            if (numOfRecords > 0)
                            {
                                command.CommandText = deleteCommandText;
                                command.ExecuteNonQuery();
                                count += numOfRecords;
                            }
                        }

                        transCommand.CommandText = "COMMIT TRANSACTION";
                        transCommand.ExecuteNonQuery();
                    }
                }
                catch
                {
                    try
                    {
                        if (beginTransCalled)
                        {
                            OleDbCommand rollbackCommand = new OleDbCommand("ROLLBACK TRANSACTION", connection);
                            rollbackCommand.ExecuteNonQuery();
                        }
                    }
                    catch
                    {
                    }
                    throw;
                }
                finally
                {
                    if (connectionHolder != null)
                    {
                        connectionHolder.Close();
                        connectionHolder = null;
                    }
                }
            }
            catch
            {
                throw;
            }

            return count;
        }

        private void SavePersonalizationBlob(OleDbConnection connection, int pathID, string state)
        {
            string currentDate = DateTime.Now.ToString(CultureInfo.InvariantCulture);
            OleDbCommand updateCommand = new OleDbCommand("UPDATE aspnet_PagePersonalizationAllUsers SET PageSettings = @PageSettings, LastUpdatedDate = @UpdatedDate WHERE PathId = @PathId", connection);

            updateCommand.Parameters.Add(new OleDbParameter("@PageSettings", state));
            updateCommand.Parameters.Add(new OleDbParameter("@UpdatedDate", currentDate));
            updateCommand.Parameters.Add(new OleDbParameter("@PathId", pathID));
            if (updateCommand.ExecuteNonQuery() != 1)
            {
                OleDbCommand insertCommand = new OleDbCommand("INSERT INTO aspnet_PagePersonalizationAllUsers (PathId, PageSettings, LastUpdatedDate) VALUES (@PathId, @PageSettings, @UpdatedDate)", connection);

                insertCommand.Parameters.Add(new OleDbParameter("@PathId", pathID));
                insertCommand.Parameters.Add(new OleDbParameter("@PageSettings", state));
                insertCommand.Parameters.Add(new OleDbParameter("@UpdatedDate", currentDate));
                insertCommand.ExecuteNonQuery();
            }
        }

        private void SavePersonalizationBlob(OleDbConnection connection, int pathID, int userID, string state)
        {
            DateTime now = DateTime.Now;

            OleDbCommand updateCommand = new OleDbCommand(@"UPDATE  aspnet_Users " +
                                                          @"SET     LastActivityDate = @LastActivityDate " +
                                                          @"WHERE   UserId = @UserId", connection);
            updateCommand.Parameters.Add(CreateDateTimeOleDbParameter("@LastActivityDate", now));
            updateCommand.Parameters.Add(new OleDbParameter("@UserId", userID));
            updateCommand.ExecuteNonQuery();

            string currentDate = now.ToString(CultureInfo.InvariantCulture);
            updateCommand = new OleDbCommand("UPDATE aspnet_PagePersonalizationPerUser SET PageSettings = @PageSettings, LastUpdatedDate = @UpdatedDate WHERE PathId = @PathId AND UserId = @UserId", connection);

            updateCommand.Parameters.Add(new OleDbParameter("@PageSettings", state));
            updateCommand.Parameters.Add(new OleDbParameter("@UpdatedDate", currentDate));
            updateCommand.Parameters.Add(new OleDbParameter("@PathId", pathID));
            updateCommand.Parameters.Add(new OleDbParameter("@UserId", userID));
            if (updateCommand.ExecuteNonQuery() != 1)
            {
                OleDbCommand insertCommand = new OleDbCommand("INSERT INTO aspnet_PagePersonalizationPerUser (PathId, UserId, PageSettings, LastUpdatedDate) VALUES (@PathId, @UserId, @PageSettings, @UpdatedDate)", connection);

                insertCommand.Parameters.Add(new OleDbParameter("@PathId", pathID));
                insertCommand.Parameters.Add(new OleDbParameter("@UserId", userID));
                insertCommand.Parameters.Add(new OleDbParameter("@PageSettings", state));
                insertCommand.Parameters.Add(new OleDbParameter("@UpdatedDate", currentDate));
                insertCommand.ExecuteNonQuery();
            }
        }

        protected override void SavePersonalizationBlob(WebPartManager webPartManager, string path, string userName, byte[] dataBlob)
        {
            AccessConnectionHolder connectionHolder = null;
            OleDbConnection connection = null;


            try
            {
                try
                {
                    string blobValue = Serialize(dataBlob);

                    connectionHolder = GetConnectionHolder();
                    connection = connectionHolder.Connection;

                    int applicationID = GetApplicationID(connectionHolder);
                    if (applicationID != 0)
                    {
                        int pathID = AccessConnectionHelper.GetPathID(connection, applicationID, path, /* createIfNeeded */ true);

                        if (pathID != 0)
                        {
                            if (String.IsNullOrEmpty(userName))
                            {
                                SavePersonalizationBlob(connection, pathID, blobValue);
                            }
                            else
                            {
                                int userID = AccessConnectionHelper.GetUserID(connection, applicationID, userName, /* createIfNeeded */ true);
                                if (userID != 0)
                                {
                                    SavePersonalizationBlob(connection, pathID, userID, blobValue);
                                }
                            }
                        }
                    }
                }
                finally
                {
                    if (connectionHolder != null)
                    {
                        connectionHolder.Close();
                        connectionHolder = null;
                    }
                }
            }
            catch
            {
                throw;
            }
        }

        private string Serialize(byte[] data)
        {
            if ((data == null) || (data.Length == 0))
            {
                return String.Empty;
            }
            return Convert.ToBase64String(data);
        }
    }
}
