//------------------------------------------------------------------------------
// <copyright file="AccessProfileProvider.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

namespace AccessProviders
{
    using System;
    using System.Web;
    using System.Web.Configuration;
    using System.Web.Profile;
    using System.Security.Principal;
    using System.Security.Permissions;
    using System.Globalization;
    using System.Runtime.Serialization;
    using System.ComponentModel;
    using System.Collections;
    using System.Collections.Specialized;
    using System.Data;
    using System.Data.SqlClient;
    using System.Data.SqlTypes;
    using System.Runtime.Serialization.Formatters.Binary;
    using System.IO;
    using System.Reflection;
    using System.Xml.Serialization;
    using System.Text;
    using System.Configuration.Provider;
    using System.Configuration;
    using System.Data.OleDb;
    using System.Web.Hosting;
    using System.Web.DataAccess;
    using System.Web.Util;

    public class AccessProfileProvider : ProfileProvider
    {
        private string _AppName;
        private string _DatabaseFileName;
        private int _ApplicationId = 0;
        private DateTime _ApplicationIDCacheDate;


        ////////////////////////////////////////////////////////////
        // Public properties

        public override void Initialize(string name, NameValueCollection config)
        {
            if (name == null || name.Length < 1)
                name = "AccessProfileProvider";

            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "AccessProviders Profile Provider");
            }
            base.Initialize(name, config);
            if (config == null)
                throw new ArgumentNullException("config");

            _DatabaseFileName = config["connectionStringName"];
            if (_DatabaseFileName == null || _DatabaseFileName.Length < 1)
                throw new ProviderException("Connection name not specified");
            string temp = AccessConnectionHelper.GetFileNameFromConnectionName(_DatabaseFileName, true);
            if (temp == null || temp.Length < 1)
            {
                throw new ProviderException("Connection string not found" + _DatabaseFileName);
            }
            _DatabaseFileName = temp;
            //HandlerBase.CheckAndReadRegistryValue(ref _DatabaseFileName, true);
            AccessConnectionHelper.CheckConnectionString(_DatabaseFileName);

            _AppName = config["applicationName"];
            if (string.IsNullOrEmpty(_AppName))
                _AppName = SecUtility.GetDefaultAppName();

            if (_AppName.Length > 255)
            {
                throw new ProviderException("ApplicationName exceeded max length of " + 255);
            }

            //_Description = config["description"];
            config.Remove("connectionStringName");
            config.Remove("applicationName");
            config.Remove("description");
            if (config.Count > 0)
            {
                string attribUnrecognized = config.GetKey(0);
                if (!String.IsNullOrEmpty(attribUnrecognized))
                    throw new ProviderException("Unrecognized attribute: " + attribUnrecognized);
            }
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////

        public override string ApplicationName
        {
            get { return _AppName; }
            set
            {
                if (value.Length > 255)
                    throw new ProviderException("ApplicationName exceeded max length of " + 255);
                if (_AppName != value)
                {
                    _ApplicationId = 0;
                    _AppName = value;
                }
            }
        }

        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////

        public override SettingsPropertyValueCollection GetPropertyValues(SettingsContext sc, SettingsPropertyCollection properties)
        {
            SettingsPropertyValueCollection svc = new SettingsPropertyValueCollection();
            if (properties.Count < 1)
                return svc;

            string username = (string)sc["UserName"];
            foreach (SettingsProperty prop in properties)
            {
                if (prop.SerializeAs == SettingsSerializeAs.ProviderSpecific)
                    if (prop.PropertyType.IsPrimitive || prop.PropertyType == typeof(string))
                        prop.SerializeAs = SettingsSerializeAs.String;
                    else
                        prop.SerializeAs = SettingsSerializeAs.Xml;
                svc.Add(new SettingsPropertyValue(prop));
            }

            if (!String.IsNullOrEmpty(username))
            {
                GetPropertyValuesFromDatabase(username, svc);
            }
            return svc;
        }

        private static void ParseDataFromDB(string[] names, string values, byte[] buf, SettingsPropertyValueCollection properties)
        {
            if (names == null || values == null || buf == null || properties == null)
                return;
            try
            {
                for (int iter = 0; iter < names.Length / 4; iter++)
                {
                    string name = names[iter * 4];
                    SettingsPropertyValue pp = properties[name];

                    if (pp == null) // property not found
                        continue;

                    int startPos = Int32.Parse(names[iter * 4 + 2], CultureInfo.InvariantCulture);
                    int length = Int32.Parse(names[iter * 4 + 3], CultureInfo.InvariantCulture);

                    if (length == -1 && !pp.Property.PropertyType.IsValueType) // Null Value
                    {
                        pp.PropertyValue = null;
                        pp.IsDirty = false;
                        pp.Deserialized = true;
                    }
                    if (names[iter * 4 + 1] == "S" && startPos >= 0 && length > 0 && values.Length >= startPos + length)
                    {
                        pp.PropertyValue = Deserialize(pp, values.Substring(startPos, length));
                    }

                    if (names[iter * 4 + 1] == "B" && startPos >= 0 && length > 0 && buf.Length >= startPos + length)
                    {
                        byte[] buf2 = new byte[length];

                        Buffer.BlockCopy(buf, startPos, buf2, 0, length);
                        pp.PropertyValue = Deserialize(pp, buf2);
                    }
                }
            }
            catch
            { // Eat exceptions
            }
        }

        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////
        private void GetPropertyValuesFromDatabase(string username, SettingsPropertyValueCollection svc)
        {
            try
            {
                AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
                string[] names = null;
                string values = null;
                OleDbDataReader reader = null;
                ////////////////////////////////////////////////////////////
                // Step 1: Get Values from DB
                try
                {
                    int appId = GetApplicationId(holder);
                    int userId = AccessConnectionHelper.GetUserID(holder.Connection, appId, username, false);

                    if (userId != 0)
                    { // User exists?
                        OleDbCommand cmd = new OleDbCommand(@"SELECT PropertyNames, PropertyValuesString " +
                                                            @"FROM aspnet_Profile " +
                                                            @"WHERE UserId = @UserId",
                                                            holder.Connection);
                        cmd.Parameters.Add(new OleDbParameter("@UserId", userId));
                        reader = cmd.ExecuteReader();
                        if (reader.Read())
                        {
                            names = reader.GetString(0).Split(':');
                            values = reader.GetString(1);
                        }
                        try
                        { // Not a critical part -- don't throw exceptions here
                            cmd = new OleDbCommand(@"UPDATE aspnet_Users SET LastActivityDate=@LastActivityDate WHERE UserId = @UserId", holder.Connection);
                            cmd.Parameters.Add(CreateDateTimeOleDbParameter("@LastActivityDate", DateTime.Now));
                            cmd.Parameters.Add(new OleDbParameter("@UserId", userId));
                            cmd.ExecuteNonQuery();
                        }
                        catch { }
                    }
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
                if (names != null && names.Length > 0)
                {
                    ParseDataFromDB(names, values, new byte[0], svc);
                }
            }
            catch
            {
                throw;
            }
        }

        private static void PrepareDataForSaving(ref string allNames, ref string allValues, ref byte[] buf, bool binarySupported, SettingsPropertyValueCollection properties, bool userIsAuthenticated)
        {
            StringBuilder names = new StringBuilder();
            StringBuilder values = new StringBuilder();

            MemoryStream ms = (binarySupported ? new System.IO.MemoryStream() : null);
            try
            {
                try
                {
                    bool anyItemsToSave = false;

                    foreach (SettingsPropertyValue pp in properties)
                    {
                        if (pp.IsDirty)
                        {
                            if (!userIsAuthenticated)
                            {
                                bool allowAnonymous = (bool)pp.Property.Attributes["AllowAnonymous"];
                                if (!allowAnonymous)
                                    continue;
                            }
                            anyItemsToSave = true;
                            break;
                        }
                    }

                    if (!anyItemsToSave)
                        return;

                    foreach (SettingsPropertyValue pp in properties)
                    {
                        if (!userIsAuthenticated)
                        {
                            bool allowAnonymous = (bool)pp.Property.Attributes["AllowAnonymous"];
                            if (!allowAnonymous)
                                continue;
                        }

                        if (!pp.IsDirty && pp.UsingDefaultValue) // Not fetched from DB and not written to
                            continue;

                        int len = 0, startPos = 0;
                        string propValue = null;

                        if (pp.Deserialized && pp.PropertyValue == null)
                        { // is value null?
                            len = -1;
                        }
                        else
                        {
                            object sVal = SerializePropertyValue(pp);

                            if (sVal == null)
                            {
                                len = -1;
                            }
                            else
                            {
                                if (!(sVal is string) && !binarySupported)
                                {
                                    sVal = Convert.ToBase64String((byte[])sVal);
                                }

                                if (sVal is string)
                                {
                                    propValue = (string)sVal;
                                    len = propValue.Length;
                                    startPos = values.Length;
                                }
                                else
                                {
                                    byte[] b2 = (byte[])sVal;
                                    startPos = (int)ms.Position;
                                    ms.Write(b2, 0, b2.Length);
                                    ms.Position = startPos + b2.Length;
                                    len = b2.Length;
                                }
                            }
                        }

                        names.Append(pp.Name + ":" + ((propValue != null) ? "S" : "B") +
                                     ":" + startPos.ToString(CultureInfo.InvariantCulture) + ":" + len.ToString(CultureInfo.InvariantCulture) + ":");
                        if (propValue != null)
                            values.Append(propValue);
                    }

                    if (binarySupported)
                    {
                        buf = ms.ToArray();
                    }
                }
                finally
                {
                    if (ms != null)
                        ms.Close();
                }
            }
            catch
            {
                throw;
            }
            allNames = names.ToString();
            allValues = values.ToString();
        }

        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////

        public override void SetPropertyValues(SettingsContext sc, SettingsPropertyValueCollection properties)
        {
            try
            {
                string username = (string)sc["UserName"];
                bool userIsAuthenticated = (bool)sc["IsAuthenticated"];
                if (username == null || username.Length < 1 || properties.Count < 1)
                    return;

                string names = String.Empty;
                string values = String.Empty;
                byte[] buf = null;
                PrepareDataForSaving(ref names, ref values, ref buf, false, properties, userIsAuthenticated);
                if (names.Length == 0)
                    return;

                ////////////////////////////////////////////////////////////
                // Step 2: Store strings in DB
                AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
                bool fBeginTransCalled = false;
                try
                {
                    OleDbCommand cmd = new OleDbCommand("BEGIN TRANSACTION", holder.Connection);
                    cmd.ExecuteNonQuery();
                    fBeginTransCalled = true;

                    int appId = GetApplicationId(holder);
                    int userId = AccessConnectionHelper.GetUserID(holder.Connection, appId, username, true, !userIsAuthenticated);

                    if (userId == 0)
                    { // User not creatable
                        return;
                    }
                    cmd = new OleDbCommand(@"SELECT UserId FROM aspnet_Profile WHERE UserId = @UserId", holder.Connection);
                    cmd.Parameters.Add(new OleDbParameter("@UserId", userId));
                    object result = cmd.ExecuteScalar();
                    if (result != null && (result is int) && ((int)result) == userId)
                    {
                        cmd = new OleDbCommand(@"UPDATE aspnet_Profile SET PropertyNames = @PropertyNames, PropertyValuesString = @PropertyValuesString, LastUpdatedDate = @LastUpdatedDate WHERE UserId = @UserId", holder.Connection);
                        cmd.Parameters.Add(new OleDbParameter("@PropertyNames", names));
                        cmd.Parameters.Add(new OleDbParameter("@PropertyValuesString", values));
                        cmd.Parameters.Add(CreateDateTimeOleDbParameter("@LastUpdatedDate", DateTime.Now));
                        cmd.Parameters.Add(new OleDbParameter("@UserId", userId));
                    }
                    else
                    {
                        cmd = new OleDbCommand(@"INSERT INTO aspnet_Profile (UserId, PropertyNames, PropertyValuesString, LastUpdatedDate) VALUES (@UserId, @PropertyNames, @PropertyValuesString, @LastUpdatedDate)", holder.Connection);
                        cmd.Parameters.Add(new OleDbParameter("@UserId", userId));
                        cmd.Parameters.Add(new OleDbParameter("@PropertyNames", names));
                        cmd.Parameters.Add(new OleDbParameter("@PropertyValuesString", values));
                        cmd.Parameters.Add(CreateDateTimeOleDbParameter("@LastUpdatedDate", DateTime.Now));
                    }
                    cmd.ExecuteNonQuery();
                    try
                    { // Not a critical part -- don't throw exceptions here
                        cmd = new OleDbCommand(@"UPDATE aspnet_Users SET LastActivityDate=@LastActivityDate WHERE UserId = @UserId", holder.Connection);
                        cmd.Parameters.Add(CreateDateTimeOleDbParameter("@LastActivityDate", DateTime.Now));
                        cmd.Parameters.Add(new OleDbParameter("@UserId", userId));
                        cmd.ExecuteNonQuery();
                    }
                    catch { }
                    cmd = new OleDbCommand("COMMIT TRANSACTION", holder.Connection);
                    cmd.ExecuteNonQuery();
                    fBeginTransCalled = false;
                }
                catch (Exception e)
                {
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    if (fBeginTransCalled)
                    {
                        try
                        {
                            OleDbCommand command = new OleDbCommand("ROLLBACK TRANSACTION", holder.Connection);
                            command.ExecuteNonQuery();
                        }
                        catch { }
                    }
                    holder.Close();
                }
            }
            catch
            {
                throw;
            }
        }


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
            throw new ProviderException("Could not get ApplicationId");
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        // Mangement APIs from ProfileProvider class

        public override int DeleteProfiles(ProfileInfoCollection profiles)
        {
            if (profiles == null)
            {
                throw new ArgumentNullException("profiles");
            }

            if (profiles.Count < 1)
            {
                throw new ArgumentException("Profiles collection is empty", "profiles");
            }

            foreach (ProfileInfo pi in profiles)
            {
                string username = pi.UserName;
                SecUtility.CheckParameter(ref username, true, true, true, 255, "UserName");
            }

            try
            {
                AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
                bool fBeginTransCalled = false;
                int numDeleted = 0;
                try
                {
                    OleDbCommand cmd = new OleDbCommand("BEGIN TRANSACTION", holder.Connection);
                    cmd.ExecuteNonQuery();
                    fBeginTransCalled = true;
                    int appId = GetApplicationId(holder);
                    foreach (ProfileInfo profile in profiles)
                        if (DeleteProfile(holder, profile.UserName.Trim(), appId))
                            numDeleted++;
                    cmd = new OleDbCommand("COMMIT TRANSACTION", holder.Connection);
                    cmd.ExecuteNonQuery();
                    fBeginTransCalled = false;
                }
                catch (Exception e)
                {
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    if (fBeginTransCalled)
                    {
                        try
                        {
                            OleDbCommand command = new OleDbCommand("ROLLBACK TRANSACTION", holder.Connection);
                            command.ExecuteNonQuery();
                        }
                        catch { }
                    }
                    holder.Close();
                }
                return numDeleted;
            }
            catch
            {
                throw;
            }
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        public override int DeleteProfiles(string[] usernames)
        {
            SecUtility.CheckArrayParameter(ref usernames,
                                            true,
                                            true,
                                            true,
                                            255,
                                            "usernames");
            try
            {
                AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
                int numDeleted = 0;
                bool fBeginTransCalled = false;
                try
                {
                    OleDbCommand cmd = new OleDbCommand("BEGIN TRANSACTION", holder.Connection);
                    cmd.ExecuteNonQuery();
                    fBeginTransCalled = true;
                    int appId = GetApplicationId(holder);
                    foreach (string username in usernames)
                        if (DeleteProfile(holder, username, appId))
                            numDeleted++;
                    cmd = new OleDbCommand("COMMIT TRANSACTION", holder.Connection);
                    cmd.ExecuteNonQuery();
                    fBeginTransCalled = false;
                }
                catch (Exception e)
                {
                    throw AccessConnectionHelper.GetBetterException(e, holder);
                }
                finally
                {
                    if (fBeginTransCalled)
                    {
                        try
                        {
                            OleDbCommand command = new OleDbCommand("ROLLBACK TRANSACTION", holder.Connection);
                            command.ExecuteNonQuery();
                        }
                        catch { }
                    }
                    holder.Close();
                }
                return numDeleted;
            }
            catch
            {
                throw;
            }
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        public override int DeleteInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate)
        {
            try
            {
                AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
                try
                {
                    string inClause = @"SELECT UserId FROM aspnet_Users " +
                        @"WHERE ApplicationId = @AppId AND LastActivityDate <= @LastActivityDate " + GetClauseForAuthenticationOptions(authenticationOption);
                    string sqlQuery = @"DELETE FROM aspnet_Profile WHERE UserId IN (" + inClause + ")";
                    OleDbCommand cmd = new OleDbCommand(sqlQuery, holder.Connection);
                    cmd.Parameters.Add(new OleDbParameter("@AppId", GetApplicationId(holder)));
                    cmd.Parameters.Add(CreateDateTimeOleDbParameter("@LastActivityDate", userInactiveSinceDate));
                    return cmd.ExecuteNonQuery();
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

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        public override int GetNumberOfInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate)
        {
            try
            {
                AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
                try
                {
                    string sqlQuery = @"SELECT COUNT(*) FROM aspnet_Users u, aspnet_Profile p " +
                        @"WHERE ApplicationId = @AppId AND LastActivityDate <= @LastActivityDate AND u.UserId = p.UserId" + GetClauseForAuthenticationOptions(authenticationOption);

                    OleDbCommand cmd = new OleDbCommand(sqlQuery, holder.Connection);
                    cmd.Parameters.Add(new OleDbParameter("@AppId", GetApplicationId(holder)));
                    cmd.Parameters.Add(CreateDateTimeOleDbParameter("@LastActivityDate", userInactiveSinceDate));
                    return (int)cmd.ExecuteScalar();
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

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        public override ProfileInfoCollection GetAllProfiles(ProfileAuthenticationOption authenticationOption, int pageIndex, int pageSize, out int totalRecords)
        {
            string sqlQuery = @"SELECT u.UserName, u.IsAnonymous, u.LastActivityDate, p.LastUpdatedDate, LEN(p.PropertyNames) + LEN(p.PropertyValuesString) " +
                              @"FROM aspnet_Users u, aspnet_Profile p " +
                              @"WHERE ApplicationId = @AppId AND u.UserId = p.UserId " +
                                    GetClauseForAuthenticationOptions(authenticationOption);
            OleDbParameter[] args = new OleDbParameter[0];
            return GetProfilesForQuery(sqlQuery, args, pageIndex, pageSize, out totalRecords);
        }


        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        public override ProfileInfoCollection GetAllInactiveProfiles(ProfileAuthenticationOption authenticationOption, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
        {
            string sqlQuery = @"SELECT u.UserName, u.IsAnonymous, u.LastActivityDate, p.LastUpdatedDate, LEN(p.PropertyNames) + LEN(p.PropertyValuesString) " +
                              @"FROM aspnet_Users u, aspnet_Profile p " +
                              @"WHERE ApplicationId = @AppId AND u.UserId = p.UserId AND u.LastActivityDate <= @LastActivityDate" +
                                   GetClauseForAuthenticationOptions(authenticationOption);

            OleDbParameter[] args = new OleDbParameter[1];
            args[0] = CreateDateTimeOleDbParameter("@LastActivityDate", userInactiveSinceDate);
            return GetProfilesForQuery(sqlQuery, args, pageIndex, pageSize, out totalRecords);
        }
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        public override ProfileInfoCollection FindProfilesByUserName(ProfileAuthenticationOption authenticationOption, string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            SecUtility.CheckParameter(ref usernameToMatch, true, true, false, 255, "username");

            string sqlQuery = @"SELECT u.UserName, u.IsAnonymous, u.LastActivityDate, p.LastUpdatedDate, LEN(p.PropertyNames) + LEN(p.PropertyValuesString) " +
                              @"FROM aspnet_Users u, aspnet_Profile p " +
                              @"WHERE ApplicationId = @AppId AND u.UserId = p.UserId AND u.UserName LIKE @UserName" +
                                  GetClauseForAuthenticationOptions(authenticationOption);
            OleDbParameter[] args = new OleDbParameter[1];
            args[0] = new OleDbParameter("@UserName", usernameToMatch);
            return GetProfilesForQuery(sqlQuery, args, pageIndex, pageSize, out totalRecords);
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        public override ProfileInfoCollection FindInactiveProfilesByUserName(ProfileAuthenticationOption authenticationOption, string usernameToMatch, DateTime userInactiveSinceDate, int pageIndex, int pageSize, out int totalRecords)
        {
            SecUtility.CheckParameter(ref usernameToMatch, true, true, false, 255, "usernameToMatch");
            string sqlQuery = @"SELECT u.UserName, u.IsAnonymous, u.LastActivityDate, p.LastUpdatedDate, LEN(p.PropertyNames) + LEN(p.PropertyValuesString) " +
                              @"FROM aspnet_Users u, aspnet_Profile p " +
                              @"WHERE ApplicationId = @AppId AND u.UserId = p.UserId AND u.UserName like @UserName AND u.LastActivityDate <= @LastActivityDate" +
                                     GetClauseForAuthenticationOptions(authenticationOption);
            OleDbParameter[] args = new OleDbParameter[2];
            args[0] = new OleDbParameter("@UserName", usernameToMatch);
            args[1] = CreateDateTimeOleDbParameter("@LastActivityDate", userInactiveSinceDate);
            return GetProfilesForQuery(sqlQuery, args, pageIndex, pageSize, out totalRecords);
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        // Private methods

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        private ProfileInfoCollection GetProfilesForQuery(string sqlQuery, OleDbParameter[] args, int pageIndex, int pageSize, out int totalRecords)
        {
            if (pageIndex < 0)
                throw new ArgumentException("Page index must be non-negative", "pageIndex");
            if (pageSize < 1)
                throw new ArgumentException("Page size must be positive", "pageSize");

            long lBound = (long)pageIndex * pageSize;
            long uBound = lBound + pageSize - 1;

            if (uBound > System.Int32.MaxValue)
            {
                throw new ArgumentException("pageIndex*pageSize too large");
            }
            try
            {
                AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
                ProfileInfoCollection profiles = new ProfileInfoCollection();
                OleDbDataReader reader = null;
                try
                {
                    OleDbCommand cmd = new OleDbCommand(sqlQuery, holder.Connection);
                    cmd.Parameters.Add(new OleDbParameter("@AppId", GetApplicationId(holder)));
                    int len = args.Length;
                    for (int iter = 0; iter < len; iter++)
                        cmd.Parameters.Add(args[iter]);
                    reader = cmd.ExecuteReader(CommandBehavior.SequentialAccess);
                    totalRecords = 0;
                    while (reader.Read())
                    {
                        totalRecords++;
                        if (totalRecords - 1 < lBound || totalRecords - 1 > uBound)
                            continue;

                        string username;
                        DateTime dtLastActivity, dtLastUpdated;
                        bool isAnon;

                        username = reader.GetString(0);
                        isAnon = reader.GetBoolean(1);
                        dtLastActivity = reader.GetDateTime(2);
                        dtLastUpdated = reader.GetDateTime(3);
                        int size = reader.GetInt32(4);
                        profiles.Add(new ProfileInfo(username, isAnon, dtLastActivity, dtLastUpdated, size));
                    }
                    return profiles;
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

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        private bool DeleteProfile(AccessConnectionHolder holder, string username, int appId)
        {
            SecUtility.CheckParameter(ref username, true, true, true, 255, "username");

            int userId = AccessConnectionHelper.GetUserID(holder.Connection, appId, username, false);
            if (userId == 0)
                return false;
            OleDbCommand cmd = new OleDbCommand(@"DELETE FROM aspnet_Profile WHERE UserId = @UserId", holder.Connection);
            cmd.Parameters.Add(new OleDbParameter("@UserId", userId));
            return (cmd.ExecuteNonQuery() != 0);
        }
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        static private string GetClauseForAuthenticationOptions(ProfileAuthenticationOption authenticationOption)
        {
            switch (authenticationOption)
            {
                case ProfileAuthenticationOption.Anonymous:
                    return " AND IsAnonymous=Yes ";

                case ProfileAuthenticationOption.Authenticated:
                    return " AND IsAnonymous=No ";

                case ProfileAuthenticationOption.All:
                    return " ";
            }
            return " ";
        }
        private OleDbParameter CreateDateTimeOleDbParameter(string parameterName, DateTime dt)
        {
            OleDbParameter p = new OleDbParameter(parameterName, OleDbType.DBTimeStamp);
            p.Direction = ParameterDirection.Input;
            p.Value = AccessConnectionHelper.RoundToSeconds(dt);
            return p;
        }

        private static string ConvertObjectToString(object propValue, Type type, SettingsSerializeAs serializeAs, bool throwOnError)
        {
            if (serializeAs == SettingsSerializeAs.ProviderSpecific)
            {
                if (type == typeof(string) || type.IsPrimitive)
                    serializeAs = SettingsSerializeAs.String;
                else
                    serializeAs = SettingsSerializeAs.Xml;
            }

            try
            {
                switch (serializeAs)
                {
                    case SettingsSerializeAs.String:
                        TypeConverter converter = TypeDescriptor.GetConverter(type);
                        if (converter != null && converter.CanConvertTo(typeof(String)) && converter.CanConvertFrom(typeof(String)))
                            return converter.ConvertToString(propValue);
                        throw new ArgumentException("Unable to convert type " + type.ToString() + " to string", "type");
                    case SettingsSerializeAs.Binary:
                        MemoryStream ms = new System.IO.MemoryStream();
                        try
                        {
                            BinaryFormatter bf = new BinaryFormatter();
                            bf.Serialize(ms, propValue);
                            byte[] buffer = ms.ToArray();
                            return Convert.ToBase64String(buffer);
                        }
                        finally
                        {
                            ms.Close();
                        }

                    case SettingsSerializeAs.Xml:
                        XmlSerializer xs = new XmlSerializer(type);
                        StringWriter sw = new StringWriter(CultureInfo.InvariantCulture);

                        xs.Serialize(sw, propValue);
                        return sw.ToString();
                }
            }
            catch (Exception)
            {
                if (throwOnError)
                    throw;
            }
            return null;
        }
        private static object SerializePropertyValue(SettingsPropertyValue prop)
        {
            object val = prop.PropertyValue;
            if (val == null)
                return null;

            if (prop.Property.SerializeAs != SettingsSerializeAs.Binary)
                return ConvertObjectToString(val, prop.Property.PropertyType, prop.Property.SerializeAs, prop.Property.ThrowOnErrorSerializing);

            MemoryStream ms = new System.IO.MemoryStream();
            try
            {
                BinaryFormatter bf = new BinaryFormatter();
                bf.Serialize(ms, val);
                return ms.ToArray();
            }
            finally
            {
                ms.Close();
            }
        }

        private static object Deserialize(SettingsPropertyValue prop, object obj)
        {
            object val = null;

            //////////////////////////////////////////////
            /// Step 1: Try creating from Serailized value
            if (obj != null)
            {
                try
                {
                    if (obj is string)
                    {
                        val = GetObjectFromString(prop.Property.PropertyType, prop.Property.SerializeAs, (string)obj);
                    }
                    else
                    {
                        MemoryStream ms = new System.IO.MemoryStream((byte[])obj);
                        try
                        {
                            val = (new BinaryFormatter()).Deserialize(ms);
                        }
                        finally
                        {
                            ms.Close();
                        }
                    }
                }
                catch
                {
                }

                if (val != null && !prop.Property.PropertyType.IsAssignableFrom(val.GetType())) // is it the correct type
                    val = null;
            }

            //////////////////////////////////////////////
            /// Step 2: Try creating from default value
            if (val == null)
            {
                if (prop.Property.DefaultValue == null || prop.Property.DefaultValue.ToString() == "[null]")
                {
                    if (prop.Property.PropertyType.IsValueType)
                        return Activator.CreateInstance(prop.Property.PropertyType);
                    else
                        return null;
                }
                if (!(prop.Property.DefaultValue is string))
                {
                    val = prop.Property.DefaultValue;
                }
                else
                {
                    try
                    {
                        val = GetObjectFromString(prop.Property.PropertyType, prop.Property.SerializeAs, (string)prop.Property.DefaultValue);
                    }
                    catch (Exception e)
                    {
                        throw new ArgumentException("Could not create from default value for property: " + prop.Property.Name, e.Message);
                    }
                }
                if (val != null && !prop.Property.PropertyType.IsAssignableFrom(val.GetType())) // is it the correct type
                    throw new ArgumentException("Could not create from default value for property: " + prop.Property.Name);
            }

            //////////////////////////////////////////////
            /// Step 3: Create a new one by calling the parameterless constructor
            if (val == null)
            {
                if (prop.Property.PropertyType == typeof(string))
                {
                    val = "";
                }
                else
                {
                    try
                    {
                        val = Activator.CreateInstance(prop.Property.PropertyType);
                    }
                    catch { }
                }
            }
            return val;
        }

        private static object GetObjectFromString(Type type, SettingsSerializeAs serializeAs, string attValue)
        {
            // Deal with string types
            if (type == typeof(string) && (attValue == null || attValue.Length < 1 || serializeAs == SettingsSerializeAs.String))
                return attValue;

            // Return null if there is nothing to convert
            if (attValue == null || attValue.Length < 1)
                return null;

            // Convert based on the serialized type
            switch (serializeAs)
            {
                case SettingsSerializeAs.Binary:
                    byte[] buf = Convert.FromBase64String(attValue);
                    MemoryStream ms = null;
                    try
                    {
                        ms = new System.IO.MemoryStream(buf);
                        return (new BinaryFormatter()).Deserialize(ms);
                    }
                    finally
                    {
                        if (ms != null)
                            ms.Close();
                    }

                case SettingsSerializeAs.Xml:
                    StringReader sr = new StringReader(attValue);
                    XmlSerializer xs = new XmlSerializer(type);
                    return xs.Deserialize(sr);

                case SettingsSerializeAs.String:
                    TypeConverter converter = TypeDescriptor.GetConverter(type);
                    if (converter != null && converter.CanConvertTo(typeof(String)) && converter.CanConvertFrom(typeof(String)))
                        return converter.ConvertFromString(attValue);
                    throw new ArgumentException("Unable to convert type: " + type.ToString() + " from string", "type");

                default:
                    return null;
            }
        }

    }
}
