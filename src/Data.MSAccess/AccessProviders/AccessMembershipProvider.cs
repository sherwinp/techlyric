//------------------------------------------------------------------------------
// <copyright file="AccessMembershipProvider.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//------------------------------------------------------------------------------

namespace AccessProviders
{
    using System;
    using System.Web;
    using System.Web.Hosting;
    using System.Web.Security;
    using System.Web.Configuration;
    using System.Security.Principal;
    using System.Security.Permissions;
    using System.Globalization;
    using System.Runtime.Serialization;
    using System.Collections;
    using System.Collections.Specialized;
    using System.Data;
    using System.Data.SqlClient;
    using System.Data.SqlTypes;
    using System.Security.Cryptography;
    using System.Text;
    using System.Text.RegularExpressions;
    using System.Configuration.Provider;
    using System.Configuration;
    using System.Data.OleDb;
    using System.Web.DataAccess;
    using System.Web.Management;
    using System.Web.Util;

    public class AccessMembershipProvider : MembershipProvider
    {
        private const int SALT_SIZE_IN_BYTES = 16;

        ////////////////////////////////////////////////////////////
        // Public properties

        public override bool EnablePasswordRetrieval { get { return _EnablePasswordRetrieval; } }

        public override bool EnablePasswordReset { get { return _EnablePasswordReset; } }

        public override bool RequiresQuestionAndAnswer { get { return _RequiresQuestionAndAnswer; } }

        public override bool RequiresUniqueEmail { get { return _RequiresUniqueEmail; } }

        public override MembershipPasswordFormat PasswordFormat { get { return _PasswordFormat; } }

        public override int MaxInvalidPasswordAttempts { get { return _MaxInvalidPasswordAttempts; } }
        public override int PasswordAttemptWindow { get { return _PasswordAttemptWindow; } }

        public override int MinRequiredPasswordLength
        {
            get { return _MinRequiredPasswordLength; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return _MinRequiredNonalphanumericCharacters; }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { return _PasswordStrengthRegularExpression; }
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

        private bool _EnablePasswordRetrieval;
        private bool _EnablePasswordReset;
        private bool _RequiresQuestionAndAnswer;
        private string _AppName;
        private bool _RequiresUniqueEmail;
        private string _DatabaseFileName;
        private string _HashAlgorithmType;
        private int _ApplicationId = 0;
        private int _MaxInvalidPasswordAttempts;
        private int _PasswordAttemptWindow;
        private int _MinRequiredPasswordLength;
        private int _MinRequiredNonalphanumericCharacters;
        private string _PasswordStrengthRegularExpression;
        private DateTime _ApplicationIDCacheDate;
        private MembershipPasswordFormat _PasswordFormat;

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("config");
            if (String.IsNullOrEmpty(name))
                name = "AccessMembershipProvider";
            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Membership AccessProviders Provider");
            }
            base.Initialize(name, config);

            _EnablePasswordRetrieval = SecUtility.GetBooleanValue(config, "enablePasswordRetrieval", false);
            _EnablePasswordReset = SecUtility.GetBooleanValue(config, "enablePasswordReset", true);
            _RequiresQuestionAndAnswer = SecUtility.GetBooleanValue(config, "requiresQuestionAndAnswer", true);
            _RequiresUniqueEmail = SecUtility.GetBooleanValue(config, "requiresUniqueEmail", true);
            _MaxInvalidPasswordAttempts = SecUtility.GetIntValue(config, "maxInvalidPasswordAttempts", 5, false, 0);
            _PasswordAttemptWindow = SecUtility.GetIntValue(config, "passwordAttemptWindow", 10, false, 0);
            _MinRequiredPasswordLength = SecUtility.GetIntValue(config, "minRequiredPasswordLength", 7, false, 128);
            _MinRequiredNonalphanumericCharacters = SecUtility.GetIntValue(config, "minRequiredNonalphanumericCharacters", 1, true, 128);

            _HashAlgorithmType = config["hashAlgorithmType"];
            if (String.IsNullOrEmpty(_HashAlgorithmType))
            {
                _HashAlgorithmType = "SHA1";
            }

            _PasswordStrengthRegularExpression = config["passwordStrengthRegularExpression"];
            if (_PasswordStrengthRegularExpression != null)
            {
                _PasswordStrengthRegularExpression = _PasswordStrengthRegularExpression.Trim();
                if (_PasswordStrengthRegularExpression.Length != 0)
                {
                    try
                    {
                        Regex regex = new Regex(_PasswordStrengthRegularExpression);
                    }
                    catch (ArgumentException e)
                    {
                        throw new ProviderException(e.Message, e);
                    }
                }
            }
            else
            {
                _PasswordStrengthRegularExpression = string.Empty;
            }

            _AppName = config["applicationName"];
            if (string.IsNullOrEmpty(_AppName))
                _AppName = SecUtility.GetDefaultAppName();

            if (_AppName.Length > 255)
            {
                throw new ProviderException("Provider application name is too long, max length is 255.");
            }

            string strTemp = config["passwordFormat"];
            if (strTemp == null)
                strTemp = "Hashed";

            switch (strTemp)
            {
                case "Clear":
                    _PasswordFormat = MembershipPasswordFormat.Clear;
                    break;
                case "Encrypted":
                    _PasswordFormat = MembershipPasswordFormat.Encrypted;
                    break;
                case "Hashed":
                    _PasswordFormat = MembershipPasswordFormat.Hashed;
                    break;
                default:
                    throw new ProviderException("Bad password format");
            }

            if (_PasswordFormat == MembershipPasswordFormat.Hashed && _EnablePasswordRetrieval)
                throw new ProviderException("Provider cannot retrieve hashed password");

            _DatabaseFileName = config["connectionStringName"];
            if (_DatabaseFileName == null || _DatabaseFileName.Length < 1)
                throw new ProviderException("Connection name not specified");

            string temp = AccessConnectionHelper.GetFileNameFromConnectionName(_DatabaseFileName, true);
            if (temp == null || temp.Length < 1)
                throw new ProviderException("Connection string not found: " + _DatabaseFileName);
            _DatabaseFileName = temp;

            // Make sure connection is good
            AccessConnectionHelper.CheckConnectionString(_DatabaseFileName);

            config.Remove("connectionStringName");
            config.Remove("enablePasswordRetrieval");
            config.Remove("enablePasswordReset");
            config.Remove("requiresQuestionAndAnswer");
            config.Remove("applicationName");
            config.Remove("requiresUniqueEmail");
            config.Remove("maxInvalidPasswordAttempts");
            config.Remove("passwordAttemptWindow");
            config.Remove("passwordFormat");
            config.Remove("name");
            config.Remove("description");
            config.Remove("minRequiredPasswordLength");
            config.Remove("minRequiredNonalphanumericCharacters");
            config.Remove("passwordStrengthRegularExpression");
            config.Remove("hashAlgorithmType");
            if (config.Count > 0)
            {
                string attribUnrecognized = config.GetKey(0);
                if (!String.IsNullOrEmpty(attribUnrecognized))
                    throw new ProviderException("Provider unrecognized attribute: " + attribUnrecognized);
            }
        }

        private string GenerateSalt()
        {
            byte[] buf = new byte[SALT_SIZE_IN_BYTES];
            (new RNGCryptoServiceProvider()).GetBytes(buf);
            return Convert.ToBase64String(buf);
        }

        private string EncodePassword(string pass, int passwordFormat, string salt)
        {
            if (passwordFormat == 0) // MembershipPasswordFormat.Clear
                return pass;

            byte[] bIn = Encoding.Unicode.GetBytes(pass);
            byte[] bSalt = Convert.FromBase64String(salt);
            byte[] bAll = new byte[bSalt.Length + bIn.Length];
            byte[] bRet = null;

            Buffer.BlockCopy(bSalt, 0, bAll, 0, bSalt.Length);
            Buffer.BlockCopy(bIn, 0, bAll, bSalt.Length, bIn.Length);
            if (passwordFormat == 1)
            { // MembershipPasswordFormat.Hashed
                HashAlgorithm s = HashAlgorithm.Create(_HashAlgorithmType);

                // If the hash algorithm is null (and came from config), throw a config exception
                if (s == null)
                {
                    throw new ProviderException("Could not create a hash algorithm");
                }
                bRet = s.ComputeHash(bAll);
            }
            else
            {
                bRet = EncryptPassword(bAll);
            }

            return Convert.ToBase64String(bRet);
        }

        private string UnEncodePassword(string pass, int passwordFormat)
        {
            switch (passwordFormat)
            {
                case 0: // MembershipPasswordFormat.Clear:
                    return pass;
                case 1: // MembershipPasswordFormat.Hashed:
                    throw new ProviderException("Provider can not decode hashed password");
                default:
                    byte[] bIn = Convert.FromBase64String(pass);
                    byte[] bRet = DecryptPassword(bIn);
                    if (bRet == null)
                        return null;
                    return Encoding.Unicode.GetString(bRet, SALT_SIZE_IN_BYTES, bRet.Length - SALT_SIZE_IN_BYTES);
            }
        }

        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////
        ////////////////////////////////////////////////////////////

        public override MembershipUser CreateUser(string username,
                                                   string password,
                                                   string email,
                                                   string passwordQuestion,
                                                   string passwordAnswer,
                                                   bool isApproved,
                                                   object userId,
                                                   out    MembershipCreateStatus status)
        {
            if (!SecUtility.ValidateParameter(ref password,
                                               true,
                                               true,
                                               false,
                                               0))
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            string salt = GenerateSalt();
            string pass = EncodePassword(password, (int)_PasswordFormat, salt);
            if (pass.Length > 128)
            {
                status = MembershipCreateStatus.InvalidPassword;
                return null;
            }

            if (!SecUtility.ValidateParameter(ref username,
                                               true,
                                               true,
                                               true,
                                               255))
            {
                status = MembershipCreateStatus.InvalidUserName;
                return null;
            }

            if (!SecUtility.ValidateParameter(ref email,
                                               RequiresUniqueEmail,
                                               RequiresUniqueEmail,
                                               false,
                                               128))
            {
                status = MembershipCreateStatus.InvalidEmail;
                return null;
            }

            if (!SecUtility.ValidateParameter(ref passwordQuestion,
                                               RequiresQuestionAndAnswer,
                                               true,
                                               false,
                                               255))
            {
                status = MembershipCreateStatus.InvalidQuestion;
                return null;
            }

            if (!SecUtility.ValidateParameter(ref passwordAnswer,
                                               RequiresQuestionAndAnswer,
                                               true,
                                               false,
                                               128))
            {
                status = MembershipCreateStatus.InvalidAnswer;
                return null;
            }

            if (userId != null)
            {
                throw new ArgumentException("userId Parameter must be null for AccessProviders");
            }

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            bool fBeginTransCalled = false;

            try
            {
                try
                {
                    //
                    // Start transaction
                    //

                    OleDbCommand command = new OleDbCommand("BEGIN TRANSACTION", connection);
                    command.ExecuteNonQuery();
                    fBeginTransCalled = true;

                    int appId = GetAppplicationId(holder);
                    object result;
                    int uid;

                    ////////////////////////////////////////////////////////////
                    // Step 1: Check if the user exists in the Users table: create if not
                    uid = AccessConnectionHelper.GetUserID(connection, appId, username, true, false, DateTime.Now);
                    if (uid == 0)
                    { // User not created successfully!
                        status = MembershipCreateStatus.ProviderError;
                        return null;
                    }

                    ////////////////////////////////////////////////////////////
                    // Step 2: Check if the user exists in the Membership table: Error if yes.
                    command = new OleDbCommand(@"SELECT UserId FROM aspnet_Membership WHERE UserId = @UserId", connection);
                    command.Parameters.Add(new OleDbParameter("@UserId", uid));
                    result = command.ExecuteScalar();
                    if (result != null && (result is int) && ((int)result) != 0)
                    {
                        status = MembershipCreateStatus.DuplicateUserName;
                        return null;
                    }

                    ////////////////////////////////////////////////////////////
                    // Step 3: Check if Email is duplicate
                    if (RequiresUniqueEmail)
                    {
                        command = new OleDbCommand(@"SELECT u.UserId FROM aspnet_Membership m, aspnet_Users u WHERE u.ApplicationId = @AppId AND m.UserId = u.UserId AND m.Email = @Email", connection);
                        command.Parameters.Add(new OleDbParameter("@AppId", appId));
                        command.Parameters.Add(new OleDbParameter("@Email", email));
                        result = command.ExecuteScalar();
                        if (result != null && (result is int) && ((int)result) != 0)
                        {
                            status = MembershipCreateStatus.DuplicateEmail;
                            return null;
                        }
                    }

                    ////////////////////////////////////////////////////////////
                    // Step 4: Create user in Membership table
                    DateTime dt = AccessConnectionHelper.RoundToSeconds(DateTime.Now);
                    command = new OleDbCommand(@"INSERT INTO aspnet_Membership " +
                                                "(UserId, Email, [Password], PasswordFormat, PasswordSalt, PasswordQuestion, PasswordAnswer, IsApproved, CreateDate, LastLoginDate, LastPasswordChangedDate) " +
                                                "VALUES (@UserId, @Email, @Pass, @PasswordFormat, @PasswordSalt, @PasswordQuestion, @PasswordAnswer, @IsApproved, @CDate, @LLDate, @LPCDate)",
                                                connection);
                    int pFormat = (int)_PasswordFormat;
                    command.Parameters.Add(new OleDbParameter("@UserId", uid));
                    command.Parameters.Add(CreateOleDbParam("@Email", OleDbType.BSTR, email));
                    command.Parameters.Add(new OleDbParameter("@Pass", pass));
                    command.Parameters.Add(new OleDbParameter("@PasswordFormat", pFormat));
                    command.Parameters.Add(new OleDbParameter("@PasswordSalt", salt));
                    command.Parameters.Add(CreateOleDbParam("@PasswordQuestion", OleDbType.BSTR, passwordQuestion));
                    command.Parameters.Add(CreateOleDbParam("@PasswordAnswer", OleDbType.BSTR, passwordAnswer));
                    command.Parameters.Add(new OleDbParameter("@IsApproved", isApproved));
                    command.Parameters.Add(CreateDateTimeOleDbParameter("@CDate", dt));
                    command.Parameters.Add(CreateDateTimeOleDbParameter("@LLDate", dt));
                    command.Parameters.Add(CreateDateTimeOleDbParameter("@LPCDate", dt));

                    //
                    // Error inserting row
                    //

                    if (command.ExecuteNonQuery() != 1)
                    {
                        status = MembershipCreateStatus.ProviderError;
                        return null;
                    }

                    command = new OleDbCommand(@"UPDATE  aspnet_Users " +
                                                @"SET     LastActivityDate = @LastActivityDate " +
                                                @"WHERE   UserId = @UserId", connection);
                    command.Parameters.Add(CreateDateTimeOleDbParameter("@LastActivityDate", dt));
                    command.Parameters.Add(new OleDbParameter("@UserId", uid));
                    command.ExecuteNonQuery();

                    //
                    // End transaction
                    //

                    command = new OleDbCommand("COMMIT TRANSACTION", connection);
                    command.ExecuteNonQuery();
                    fBeginTransCalled = false;

                    status = MembershipCreateStatus.Success;
                    return new MembershipUser(this.Name,
                                               username,
                                               uid,
                                               email,
                                               passwordQuestion,
                                               null,
                                               isApproved,
                                               false,
                                               dt,
                                               dt,
                                               dt,
                                               dt,
                                               DateTime.MinValue);
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
                            OleDbCommand cmd = new OleDbCommand("ROLLBACK TRANSACTION",
                                                                 connection);
                            cmd.ExecuteNonQuery();
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

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            SecUtility.CheckParameter(ref username, true, true, true, 255, "username");
            SecUtility.CheckParameter(ref password, true, true, false, 128, "password");

            SecUtility.CheckParameter(
                            ref newPasswordQuestion,
                            RequiresQuestionAndAnswer,
                            true,
                            false,
                            255,
                            "newPasswordQuestion");

            SecUtility.CheckParameter(
                            ref newPasswordAnswer,
                            RequiresQuestionAndAnswer,
                            true,
                            false,
                            128,
                            "newPasswordAnswer");

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;

            try
            {
                try
                {
                    int status = 0;
                    int appId = GetAppplicationId(holder);
                    int userId = AccessConnectionHelper.GetUserID(connection, appId, username, false);
                    OleDbCommand command;

                    ////////////////////////////////////////////////////////////
                    // Step 1: Make sure user exists
                    if (userId == 0)
                    {
                        return false;
                    }

                    ////////////////////////////////////////////////////////////
                    // Step 2: Make sure password is correct
                    if (!CheckPassword(connection, userId, password, out status))
                    {
                        return false;
                    }

                    ////////////////////////////////////////////////////////////
                    // Step 3: Update table
                    command = new OleDbCommand(@"UPDATE aspnet_Membership " + @"SET PasswordQuestion = @PasswordQuestion, PasswordAnswer = @PasswordAnswer " + @"WHERE UserId = @UserId",
                        connection);

                    command.Parameters.Add(CreateOleDbParam("@PasswordQuestion", OleDbType.BSTR, newPasswordQuestion));
                    command.Parameters.Add(CreateOleDbParam("@PasswordAnswer", OleDbType.BSTR, newPasswordAnswer));
                    command.Parameters.Add(new OleDbParameter("@UserId", userId));

                    if (command.ExecuteNonQuery() != 1)
                    {
                        return false;
                    }
                    else
                    {
                        return true;
                    }
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

        public override string GetPassword(string username, string passwordAnswer)
        {
            if (!EnablePasswordRetrieval)
                throw new NotSupportedException("Membership PasswordRetrieval not supported");

            SecUtility.CheckParameter(ref username, true, true, true, 255, "username");
            SecUtility.CheckParameter(ref passwordAnswer, RequiresQuestionAndAnswer, RequiresQuestionAndAnswer, false, 128, "passwordAnswer");

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            try
            {
                try
                {
                    int appId = GetAppplicationId(holder);
                    int userId = AccessConnectionHelper.GetUserID(connection, appId, username, false);
                    int passwordFormat = 0;
                    int status = 0;
                    string pass = null;
                    string salt = null;
                    bool userIsApproved;

                    pass = GetPasswordWithFormat(connection, userId, passwordAnswer, RequiresQuestionAndAnswer,
                                                 out passwordFormat, out status, out salt, out userIsApproved);

                    if (pass == null)
                    {
                        string errText = GetExceptionText(status);

                        if (IsStatusDueToBadPassword(status))
                        {
                            throw new MembershipPasswordException(errText);
                        }
                        else
                        {
                            throw new ProviderException(errText);
                        }
                    }
                    return UnEncodePassword(pass, passwordFormat);
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
        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            SecUtility.CheckParameter(ref username, true, true, true, 255, "username");
            SecUtility.CheckParameter(ref oldPassword, true, true, false, 128, "oldPassword");
            SecUtility.CheckParameter(ref newPassword, true, true, false, 128, "newPassword");

            string salt = GenerateSalt();
            string pass = EncodePassword(newPassword, (int)_PasswordFormat, salt);
            if (pass.Length > 128)
                throw new ArgumentException("Membership password too long, max is 128");

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            try
            {
                try
                {
                    int status = 0;
                    int appId = GetAppplicationId(holder);
                    int userId = AccessConnectionHelper.GetUserID(connection, appId, username, false);
                    OleDbCommand command;

                    ////////////////////////////////////////////////////////////
                    // Step 1: Make sure user exists
                    if (userId == 0)
                    {
                        return false;
                    }

                    ////////////////////////////////////////////////////////////
                    // Step 2: Make sure oldPassword is correct
                    if (!CheckPassword(connection, userId, oldPassword, out status))
                    {
                        return false;
                    }

                    ////////////////////////////////////////////////////////////
                    // Step 3: Save new password
                    command = new OleDbCommand(@"UPDATE aspnet_Membership " +
                                                @"SET [Password] = @Pass, PasswordFormat = @PasswordFormat, PasswordSalt = @PasswordSalt, LastPasswordChangedDate = @LastPasswordChangedDate " +
                                                @"WHERE UserId = @UserId",
                                               connection);

                    int pFormat = (int)_PasswordFormat;
                    command.Parameters.Add(new OleDbParameter("@Pass", pass));
                    command.Parameters.Add(new OleDbParameter("@PasswordFormat", pFormat));
                    command.Parameters.Add(new OleDbParameter("@PasswordSalt", salt));
                    command.Parameters.Add(CreateDateTimeOleDbParameter("@LastPasswordChangedDate", DateTime.Now));
                    command.Parameters.Add(new OleDbParameter("@UserId", userId));

                    if (command.ExecuteNonQuery() != 1)
                    {
                        throw new ProviderException(GetExceptionText(100));
                    }
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

        public override string ResetPassword(string username, string passwordAnswer)
        {
            if (!EnablePasswordReset)
                throw new NotSupportedException("Not configured to support password resets");

            SecUtility.CheckParameter(ref username, true, true, true, 255, "username");
            SecUtility.CheckParameter(ref passwordAnswer, RequiresQuestionAndAnswer, RequiresQuestionAndAnswer, false, 128, "passwordAnswer");

            string salt = GenerateSalt();
            string newPassword = GeneratePassword();
            string pass = EncodePassword(newPassword, (int)_PasswordFormat, salt);

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            OleDbDataReader reader = null;
            try
            {
                try
                {
                    int appId = GetAppplicationId(holder);
                    int userId = AccessConnectionHelper.GetUserID(connection, appId, username, false);
                    OleDbCommand command;

                    ////////////////////////////////////////////////////////////
                    // Step 1: Make sure user exists
                    if (userId == 0)
                    {
                        throw new ProviderException(GetExceptionText(1));
                    }

                    ////////////////////////////////////////////////////////////
                    // Step 2: Check passwordAnswer
                    if (RequiresQuestionAndAnswer)
                    {
                        command = new OleDbCommand(@"SELECT PasswordAnswer " +
                                                    @"FROM aspnet_Membership " +
                                                    @"WHERE UserId = @UserId",
                                                    connection);
                        command.Parameters.Add(new OleDbParameter("@UserId", userId));
                        reader = command.ExecuteReader();
                        if (!reader.Read())
                        { // No passwordAnswer!
                            throw new MembershipPasswordException(GetExceptionText(3));
                        }
                        string storedPasswordAnswer = GetNullableString(reader, 0);
                        if (storedPasswordAnswer == null || String.Compare(storedPasswordAnswer, passwordAnswer, true, CultureInfo.InvariantCulture) != 0)
                        {
                            throw new MembershipPasswordException(GetExceptionText(3));
                        }
                    }

                    ////////////////////////////////////////////////////////////
                    // Step 3: Save new password
                    command = new OleDbCommand(@"UPDATE aspnet_Membership " +
                                                @"SET [Password] = @Pass, PasswordFormat = @PasswordFormat, PasswordSalt = @PasswordSalt, LastPasswordChangedDate = @LastPasswordChangedDate " +
                                                @"WHERE UserId = @UserId",
                                               connection);
                    int pFormat = (int)_PasswordFormat;
                    command.Parameters.Add(new OleDbParameter("@Pass", pass));
                    command.Parameters.Add(new OleDbParameter("@PasswordFormat", pFormat));
                    command.Parameters.Add(new OleDbParameter("@PasswordSalt", salt));
                    command.Parameters.Add(CreateDateTimeOleDbParameter("@LastPasswordChangedDate", DateTime.Now));
                    command.Parameters.Add(new OleDbParameter("@UserId", userId));

                    if (command.ExecuteNonQuery() != 1)
                    {
                        throw new ProviderException(GetExceptionText(100));
                    }
                    return newPassword;
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

        public override void UpdateUser(MembershipUser user)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }

            string temp = user.UserName;
            SecUtility.CheckParameter(ref temp, true, true, false, 255, "UserName");
            temp = user.Email;
            SecUtility.CheckParameter(ref temp, RequiresUniqueEmail, RequiresUniqueEmail, false, 128, "Email");
            user.Email = temp;

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            bool fBeginTransCalled = false;

            try
            {
                try
                {
                    int appId = GetAppplicationId(holder);
                    int userId = AccessConnectionHelper.GetUserID(connection, appId, user.UserName, false);
                    OleDbCommand command;
                    object result;

                    ////////////////////////////////////////////////////////////
                    // Step 1: Make sure user exists
                    if (userId == 0)
                    {
                        throw new ProviderException(GetExceptionText(1));
                    }
                    command = new OleDbCommand(@"SELECT UserId FROM aspnet_Membership WHERE UserId = @UserId", connection);
                    command.Parameters.Add(new OleDbParameter("@UserId", userId));

                    result = command.ExecuteScalar();
                    if (result == null || !(result is int))
                    {
                        throw new ProviderException(GetExceptionText(1));
                    }

                    ////////////////////////////////////////////////////////////
                    // Step 2: Make sure email is unique

                    if (_RequiresUniqueEmail)
                    {
                        command = new OleDbCommand(@"SELECT u.UserId " +
                                                    @"FROM aspnet_Membership m, aspnet_Users u " +
                                                    @"WHERE u.UserId <> @UserId AND m.Email = @Email AND u.UserId = m.UserId AND u.ApplicationId = @AppId",
                                                    connection);
                        command.Parameters.Add(new OleDbParameter("@UserId", userId));
                        command.Parameters.Add(new OleDbParameter("@Email", user.Email));
                        command.Parameters.Add(new OleDbParameter("@AppId", appId));

                        result = command.ExecuteScalar();
                        if (result != null && (result is int))
                        {
                            int userId2 = (int)result;
                            if (userId2 != userId)
                            {
                                throw new ProviderException("Dup user id: " + userId2.ToString(CultureInfo.InvariantCulture));
                            }
                        }
                    }

                    ////////////////////////////////////////////////////////////
                    // Step 3: Update table

                    //
                    // Start transaction
                    //

                    command = new OleDbCommand("BEGIN TRANSACTION", connection);
                    command.ExecuteNonQuery();
                    fBeginTransCalled = true;

                    command = new OleDbCommand(@"UPDATE aspnet_Membership " +
                                                @"SET Email = @Email, Comment = @Comment, LastLoginDate = @LastLoginDate, IsApproved = @IsApproved " +
                                                @"WHERE UserId = @UserId",
                                                connection);
                    int isapp = user.IsApproved ? 1 : 0;
                    string comm = (user.Comment == null) ? String.Empty : user.Comment;

                    command.Parameters.Add(CreateOleDbParam("@Email", OleDbType.BSTR, user.Email));
                    command.Parameters.Add(new OleDbParameter("@Comment", comm));
                    command.Parameters.Add(CreateDateTimeOleDbParameter("@LastLoginDate", user.LastLoginDate));
                    command.Parameters.Add(new OleDbParameter("@IsApproved", isapp));
                    command.Parameters.Add(new OleDbParameter("@UserId", userId));

                    if (command.ExecuteNonQuery() != 1)
                    {
                        throw new ProviderException(GetExceptionText(20));
                    }

                    command = new OleDbCommand(@"UPDATE aspnet_Users SET LastActivityDate = @LastActivityDate WHERE UserId = @UserId", connection);
                    command.Parameters.Add(CreateDateTimeOleDbParameter("@LastActivityDate", user.LastActivityDate));
                    command.Parameters.Add(new OleDbParameter("@UserId", userId));

                    command.ExecuteNonQuery();

                    //
                    // End transaction
                    //

                    command = new OleDbCommand("COMMIT TRANSACTION", connection);
                    command.ExecuteNonQuery();
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
                            OleDbCommand cmd = new OleDbCommand("ROLLBACK TRANSACTION",
                                                                 connection);
                            cmd.ExecuteNonQuery();
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

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override bool ValidateUser(string username, string password)
        {
            if (!SecUtility.ValidateParameter(ref username,
                                               true,
                                               true,
                                               false,
                                               255))
            {
                return false;
            }

            if (!SecUtility.ValidateParameter(ref password,
                                               true,
                                               true,
                                               false,
                                               128))
            {
                return false;
            }

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            bool fBeginTransCalled = false;

            try
            {
                try
                {
                    int appId = GetAppplicationId(holder);
                    int userId = AccessConnectionHelper.GetUserID(connection, appId, username, false);
                    bool userIsApproved = false;
                    if (CheckPassword(connection, userId, password, out userIsApproved) && userIsApproved)
                    {
                        OleDbCommand command;

                        //
                        // Start transaction
                        //

                        command = new OleDbCommand("BEGIN TRANSACTION", connection);
                        command.ExecuteNonQuery();
                        fBeginTransCalled = true;

                        command = new OleDbCommand(@"UPDATE  aspnet_Membership " +
                                                    @"SET     LastLoginDate = @LastLoginDate " +
                                                    @"WHERE   UserId = @UserId",
                                               connection);

                        command.Parameters.Add(CreateDateTimeOleDbParameter("@LastLoginDate", DateTime.Now));
                        command.Parameters.Add(new OleDbParameter("@UserId", userId));
                        command.ExecuteNonQuery();

                        command = new OleDbCommand(@"UPDATE  aspnet_Users " +
                                                    @"SET     LastActivityDate = @LastActivityDate " +
                                                    @"WHERE   UserId = @UserId", connection);
                        command.Parameters.Add(CreateDateTimeOleDbParameter("@LastActivityDate", DateTime.Now));
                        command.Parameters.Add(new OleDbParameter("@UserId", userId));
                        command.ExecuteNonQuery();

                        //
                        // End transaction
                        //

                        command = new OleDbCommand("COMMIT TRANSACTION", connection);
                        command.ExecuteNonQuery();
                        fBeginTransCalled = false;

                        return true;
                    }
                    else
                    {
                        return false;
                    }
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
                            OleDbCommand cmd = new OleDbCommand("ROLLBACK TRANSACTION",
                                                                 connection);
                            cmd.ExecuteNonQuery();
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

        public override bool UnlockUser(string userName)
        {
            return false;
        }

        public override MembershipUser GetUser(object userId, bool userIsOnline)
        {
            return null;
        }

        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            SecUtility.CheckParameter(
                            ref username,
                            true,
                            false,
                            true,
                            255,
                            "username");

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            OleDbDataReader reader = null;

            try
            {
                try
                {
                    int appId = GetAppplicationId(holder);
                    OleDbCommand command;

                    command = new OleDbCommand(@"SELECT Email, PasswordQuestion, Comment, CreateDate, LastLoginDate, LastActivityDate, LastPasswordChangedDate, u.UserId, IsApproved " +
                                                @"FROM aspnet_Users u, aspnet_Membership m " +
                                                @"WHERE u.ApplicationId = @AppId  AND u.UserName = @UserName AND u.UserId = m.UserId",
                                               connection);

                    command.Parameters.Add(new OleDbParameter("@AppId", appId));
                    command.Parameters.Add(new OleDbParameter("@UserName", username));

                    reader = command.ExecuteReader();
                    if (!reader.Read())
                    {
                        return null;
                    }

                    string email = GetNullableString(reader, 0);
                    string passwordQuestion = GetNullableString(reader, 1);
                    string comment = GetNullableString(reader, 2);
                    DateTime dtCreate = reader.GetDateTime(3);
                    DateTime dtLastLogin = reader.GetDateTime(4);
                    DateTime dtLastActivity = userIsOnline ? AccessConnectionHelper.RoundToSeconds(DateTime.Now)
                                                           : reader.GetDateTime(5);
                    DateTime dtLastPassChange = reader.GetDateTime(6);
                    int userId = reader.GetInt32(7);
                    bool isApproved = reader.GetBoolean(8);

                    if (userIsOnline)
                    {
                        command = new OleDbCommand(@"UPDATE aspnet_Users " +
                                                    @"SET LastActivityDate = @LastActivityDate " +
                                                    @"WHERE UserId = @UserId",
                                                   connection);
                        command.Parameters.Add(CreateDateTimeOleDbParameter("@LastActivityDate", dtLastActivity));
                        command.Parameters.Add(new OleDbParameter("@UserId", userId));

                        command.ExecuteNonQuery();
                    }

                    ////////////////////////////////////////////////////////////
                    // Step 4 : Return the result
                    return new MembershipUser(this.Name,
                                               username,
                                               userId,
                                               email,
                                               passwordQuestion,
                                               comment,
                                               isApproved,
                                               false,
                                               dtCreate,
                                               dtLastLogin,
                                               dtLastActivity,
                                               dtLastPassChange,
                                               DateTime.MinValue);
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

        public override string GetUserNameByEmail(string email)
        {
            SecUtility.CheckParameter(
                            ref email,
                            false,
                            false,
                            false,
                            128,
                            "email");

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            try
            {
                try
                {
                    int appId = GetAppplicationId(holder);
                    OleDbCommand command = null;
                    OleDbDataReader reader = null;
                    string username = null;

                    if (email != null)
                    {
                        command = new OleDbCommand(@"SELECT UserName " +
                                                   @"FROM aspnet_users u, aspnet_Membership m " +
                                                   @"WHERE m.Email = @Email AND u.UserId = m.UserId AND u.ApplicationId = @AppId",
                                                   connection);
                        command.Parameters.Add(CreateOleDbParam("@Email", OleDbType.BSTR, email));
                        command.Parameters.Add(new OleDbParameter("@AppId", appId));
                    }
                    else
                    {
                        command = new OleDbCommand(@"SELECT UserName " +
                                                   @"FROM aspnet_users u, aspnet_Membership m " +
                                                   @"WHERE m.Email IS NULL AND u.UserId = m.UserId AND u.ApplicationId = @AppId",
                                                   connection);
                        command.Parameters.Add(new OleDbParameter("@AppId", appId));
                    }

                    try
                    {
                        reader = command.ExecuteReader(CommandBehavior.SequentialAccess);
                        if (reader.Read())
                        {
                            username = GetNullableString(reader, 0);
                            if (RequiresUniqueEmail && reader.Read())
                            {
                                throw new ProviderException("Cannot have more than one user with the same email");
                            }
                        }
                        return username;
                    }
                    catch
                    {
                        throw;
                    }
                    finally
                    {
                        if (reader != null)
                            reader.Close();
                    }
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

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            SecUtility.CheckParameter(ref username, true, true, true, 255, "username");

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            bool fBeginTransCalled = false;

            try
            {
                try
                {
                    int appId = GetAppplicationId(holder);
                    int userId = AccessConnectionHelper.GetUserID(connection, appId, username, false);

                    if (userId == 0)
                        return false; // User not found
                    OleDbCommand command;

                    //
                    // Start transaction
                    //

                    command = new OleDbCommand("BEGIN TRANSACTION", connection);
                    command.ExecuteNonQuery();
                    fBeginTransCalled = true;

                    command = new OleDbCommand(@"DELETE FROM aspnet_Membership WHERE UserId = @UserId", connection);
                    command.Parameters.Add(new OleDbParameter("@UserId", userId));

                    bool returnValue = (command.ExecuteNonQuery() == 1);
                    if (deleteAllRelatedData)
                    {
                        command = new OleDbCommand(@"DELETE FROM aspnet_UsersInRoles WHERE UserId = @UserId", connection);
                        command.Parameters.Add(new OleDbParameter("@UserId", userId));
                        command.ExecuteNonQuery();

                        command = new OleDbCommand(@"DELETE FROM aspnet_Profile WHERE UserId = @UserId", connection);
                        command.Parameters.Add(new OleDbParameter("@UserId", userId));
                        command.ExecuteNonQuery();

                        command = new OleDbCommand(@"DELETE FROM aspnet_PagePersonalizationPerUser WHERE UserId = @UserId", connection);
                        command.Parameters.Add(new OleDbParameter("@UserId", userId));
                        command.ExecuteNonQuery();

                        command = new OleDbCommand(@"DELETE FROM aspnet_Users WHERE UserId = @UserId", connection);
                        command.Parameters.Add(new OleDbParameter("@UserId", userId));
                        returnValue = (command.ExecuteNonQuery() == 1);
                    }

                    //
                    // End transaction
                    //

                    command = new OleDbCommand("COMMIT TRANSACTION", connection);
                    command.ExecuteNonQuery();
                    fBeginTransCalled = false;

                    return returnValue;
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
                            OleDbCommand cmd = new OleDbCommand("ROLLBACK TRANSACTION",
                                                                 connection);
                            cmd.ExecuteNonQuery();
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


        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////
        //////////////////////////////////////////////////////////////////////


        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            if (pageIndex < 0)
                throw new ArgumentException("PageIndex cannot be negative");
            if (pageSize < 1)
                throw new ArgumentException("PageSize must be positive");

            long lBound = (long)pageIndex * pageSize;
            long uBound = lBound + pageSize - 1;

            if (uBound > System.Int32.MaxValue)
            {
                throw new ArgumentException("PageIndex too big");
            }

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            OleDbDataReader reader = null;
            long recordCount = 0;
            try
            {
                try
                {
                    int appId = GetAppplicationId(holder);
                    OleDbCommand command;
                    MembershipUserCollection users = new MembershipUserCollection();

                    command = new OleDbCommand(@"SELECT UserName, Email, PasswordQuestion, Comment, CreateDate, LastLoginDate, LastActivityDate, LastPasswordChangedDate, IsApproved, u.UserId " +
                                               @"FROM  aspnet_Membership m, aspnet_Users u " +
                                               @"WHERE  u.ApplicationId = @AppId AND u.UserId = m.UserId " +
                                               @"ORDER BY UserName",
                                  connection);
                    command.Parameters.Add(new OleDbParameter("@AppId", appId));

                    reader = command.ExecuteReader(CommandBehavior.SequentialAccess);

                    while (reader.Read())
                    {
                        recordCount++;
                        if (recordCount - 1 < lBound || recordCount - 1 > uBound)
                            continue;
                        string username, email, passwordQuestion, comment;
                        DateTime dtCreate, dtLastLogin, dtLastActivity, dtLastPassChange;
                        bool isApproved;
                        int userId;
                        username = GetNullableString(reader, 0);
                        email = GetNullableString(reader, 1);
                        passwordQuestion = GetNullableString(reader, 2);
                        comment = GetNullableString(reader, 3);
                        dtCreate = reader.GetDateTime(4);
                        dtLastLogin = reader.GetDateTime(5);
                        dtLastActivity = reader.GetDateTime(6);
                        dtLastPassChange = reader.GetDateTime(7);
                        isApproved = reader.GetBoolean(8);
                        userId = reader.GetInt32(9);
                        users.Add(new MembershipUser(this.Name,
                                                      username,
                                                      userId,
                                                      email,
                                                      passwordQuestion,
                                                      comment,
                                                      isApproved,
                                                      false,
                                                      dtCreate,
                                                      dtLastLogin,
                                                      dtLastActivity,
                                                      dtLastPassChange,
                                                      DateTime.MinValue));
                    }
                    totalRecords = (int)recordCount;
                    return users;
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
        /////////////////////////////////////////////////////////////////////////////

        public override int GetNumberOfUsersOnline()
        {
            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            try
            {
                try
                {
                    int appId = GetAppplicationId(holder);
                    TimeSpan ts = new TimeSpan(0, Membership.UserIsOnlineTimeWindow, 0);
                    DateTime dt = DateTime.Now.Subtract(ts);
                    object result;
                    OleDbCommand command;

                    command = new OleDbCommand(@"SELECT COUNT(*) FROM aspnet_Users u, aspnet_Membership m WHERE u.UserId = m.UserId AND ApplicationId=@AppId AND LastActivityDate > @LastActivityDate",
                                               connection);

                    command.Parameters.Add(new OleDbParameter("@AppId", appId));
                    command.Parameters.Add(CreateDateTimeOleDbParameter("@LastActivityDate", dt));
                    result = command.ExecuteScalar();

                    if (result != null && (result is int))
                        return (int)result;
                    else
                        return 0;
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
        /////////////////////////////////////////////////////////////////////////////

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            SecUtility.CheckParameter(ref usernameToMatch, true, true, false, 255, "usernameToMatch");

            if (pageIndex < 0)
                throw new ArgumentException("PageIndex cannot be negative");
            if (pageSize < 1)
                throw new ArgumentException("PageSize must be positive");

            long lBound = (long)pageIndex * pageSize;
            long uBound = lBound + pageSize - 1;

            if (uBound > System.Int32.MaxValue)
            {
                throw new ArgumentException("PageIndex too big");
            }

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            OleDbDataReader reader = null;
            long recordCount = 0;
            try
            {
                try
                {
                    int appId = GetAppplicationId(holder);
                    OleDbCommand command;
                    MembershipUserCollection users = new MembershipUserCollection();

                    command = new OleDbCommand(@"SELECT UserName, Email, PasswordQuestion, Comment, CreateDate, LastLoginDate, LastActivityDate, LastPasswordChangedDate, IsApproved, u.UserId " +
                                                @"FROM  aspnet_Membership m, aspnet_Users u " +
                                                @"WHERE  u.ApplicationId = @AppId AND u.UserId = m.UserId AND " +
                                                @"UserName like @UserName " +
                                                @"ORDER BY UserName", connection);
                    command.Parameters.Add(new OleDbParameter("@AppId", appId));
                    command.Parameters.Add(new OleDbParameter("@UserName", usernameToMatch));
                    reader = command.ExecuteReader(CommandBehavior.SequentialAccess);
                    while (reader.Read())
                    {
                        recordCount++;
                        if (recordCount - 1 < lBound || recordCount - 1 > uBound)
                            continue;

                        string username, email, passwordQuestion, comment;
                        DateTime dtCreate, dtLastLogin, dtLastActivity, dtLastPassChange;
                        bool isApproved;
                        int userId;

                        username = GetNullableString(reader, 0);
                        email = GetNullableString(reader, 1);
                        passwordQuestion = GetNullableString(reader, 2);
                        comment = GetNullableString(reader, 3);
                        dtCreate = reader.GetDateTime(4);
                        dtLastLogin = reader.GetDateTime(5);
                        dtLastActivity = reader.GetDateTime(6);
                        dtLastPassChange = reader.GetDateTime(7);
                        isApproved = reader.GetBoolean(8);
                        userId = reader.GetInt32(9);
                        users.Add(new MembershipUser(this.Name,
                                                      username,
                                                      userId,
                                                      email,
                                                      passwordQuestion,
                                                      comment,
                                                      isApproved,
                                                      false,
                                                      dtCreate,
                                                      dtLastLogin,
                                                      dtLastActivity,
                                                      dtLastPassChange,
                                                      DateTime.MinValue));
                    }
                    return users;
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
                    totalRecords = (int)recordCount;
                }
            }
            catch
            {
                throw;
            }
        }


        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            SecUtility.CheckParameter(ref emailToMatch, false, false, false, 128, "emailToMatch");

            if (pageIndex < 0)
                throw new ArgumentException("PageIndex cannot be negative");
            if (pageSize < 1)
                throw new ArgumentException("PageSize must be positive");

            long lBound = (long)pageIndex * pageSize;
            long uBound = lBound + pageSize - 1;

            if (uBound > System.Int32.MaxValue)
            {
                throw new ArgumentException("PageIndex too big");
            }

            AccessConnectionHolder holder = AccessConnectionHelper.GetConnection(_DatabaseFileName, true);
            OleDbConnection connection = holder.Connection;
            OleDbDataReader reader = null;
            long recordCount = 0;
            try
            {
                try
                {
                    int appId = GetAppplicationId(holder);
                    OleDbCommand command;
                    MembershipUserCollection users = new MembershipUserCollection();

                    if (emailToMatch != null)
                    {
                        command = new OleDbCommand(@"SELECT UserName, Email, PasswordQuestion, Comment, CreateDate, LastLoginDate, LastActivityDate, LastPasswordChangedDate, IsApproved, u.UserId "
                                                + @"FROM  aspnet_Membership m, aspnet_Users u " +
                                                @"WHERE  u.ApplicationId = @AppId AND u.UserId = m.UserId AND Email like @Email " + @"ORDER BY UserName", connection);
                        command.Parameters.Add(new OleDbParameter("@AppId", appId));
                        command.Parameters.Add(new OleDbParameter("@Email", emailToMatch));
                    }
                    else
                    {
                        command = new OleDbCommand(@"SELECT UserName, Email, PasswordQuestion, Comment, CreateDate, LastLoginDate, LastActivityDate, LastPasswordChangedDate, IsApproved, u.UserId "
                                                + @"FROM  aspnet_Membership m, aspnet_Users u " +
                                                @"WHERE  u.ApplicationId = @AppId AND u.UserId = m.UserId AND Email IS NULL " + @"ORDER BY UserName", connection);
                        command.Parameters.Add(new OleDbParameter("@AppId", appId));
                    }
                    reader = command.ExecuteReader(CommandBehavior.SequentialAccess);
                    while (reader.Read())
                    {
                        recordCount++;
                        if (recordCount - 1 < lBound || recordCount - 1 > uBound)
                            continue;

                        string username, email, passwordQuestion, comment;
                        DateTime dtCreate, dtLastLogin, dtLastActivity, dtLastPassChange;
                        bool isApproved;
                        int userId;

                        username = GetNullableString(reader, 0);
                        email = GetNullableString(reader, 1);
                        passwordQuestion = GetNullableString(reader, 2);
                        comment = GetNullableString(reader, 3);
                        dtCreate = reader.GetDateTime(4);
                        dtLastLogin = reader.GetDateTime(5);
                        dtLastActivity = reader.GetDateTime(6);
                        dtLastPassChange = reader.GetDateTime(7);
                        isApproved = reader.GetBoolean(8);
                        userId = reader.GetInt32(9);
                        users.Add(new MembershipUser(this.Name,
                                                      username,
                                                      userId,
                                                      email,
                                                      passwordQuestion,
                                                      comment,
                                                      isApproved,
                                                      false,
                                                      dtCreate,
                                                      dtLastLogin,
                                                      dtLastActivity,
                                                      dtLastPassChange,
                                                      DateTime.MinValue));
                    }
                    return users;
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
                    totalRecords = (int)recordCount;
                }
            }
            catch
            {
                throw;
            }
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        private bool CheckPassword(OleDbConnection connection, int userId, string password, out int status)
        {
            string salt;
            bool userIsApproved;
            int passwordFormat;
            string pass = GetPasswordWithFormat(connection, userId, null, false, out passwordFormat, out status, out salt, out userIsApproved);
            string pass2 = EncodePassword(password, passwordFormat, salt);
            return (pass == pass2);
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        private bool CheckPassword(OleDbConnection connection, int userId, string password, out bool userIsApproved)
        {
            string salt;
            int passwordFormat, status;
            string pass = GetPasswordWithFormat(connection, userId, null, false, out passwordFormat, out status, out salt, out userIsApproved);
            string pass2 = EncodePassword(password, passwordFormat, salt);
            return (pass == pass2);
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        private string GetPasswordWithFormat(
                            OleDbConnection connection,
                            int userId,
                            string passwordAnswer,
                            bool requiresQuestionAndAnswer,
                            out int passwordFormat,
                            out int status,
                            out string passwordSalt,
                            out bool userIsApproved)
        {
            OleDbCommand command;
            OleDbDataReader reader;
            string storedPasswordAnswer;
            string pass;

            passwordFormat = 0;
            status = 1; // status = user not found
            passwordSalt = String.Empty;
            userIsApproved = false;
            if (userId == 0)
                return null;

            command = new OleDbCommand(@"SELECT PasswordFormat, [Password], PasswordAnswer, PasswordSalt, IsApproved " +
                                        @"FROM aspnet_Membership m, aspnet_Users u " +
                                        @"WHERE m.UserId = @UserId AND m.UserId = u.UserId",
                                       connection);
            command.Parameters.Add(new OleDbParameter("@UserId", userId));

            reader = command.ExecuteReader();

            if (!reader.Read())
            { // Zero rows read = user-not-found
                reader.Close();
                return null;
            }

            passwordFormat = reader.GetInt32(0);
            pass = GetNullableString(reader, 1);
            storedPasswordAnswer = GetNullableString(reader, 2);
            passwordSalt = GetNullableString(reader, 3);
            userIsApproved = reader.GetBoolean(4);

            if (requiresQuestionAndAnswer && String.Compare(storedPasswordAnswer, passwordAnswer, true, CultureInfo.InvariantCulture) != 0)
            {
                status = 3;
                pass = null;
            }
            else
            {
                status = 0;
            }
            reader.Close();
            return pass;
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        private int GetAppplicationId(AccessConnectionHolder holder)
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
            throw new ProviderException(GetExceptionText(20));
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        private string GetNullableString(OleDbDataReader reader, int col)
        {
            if (reader.IsDBNull(col) == false)
            {
                return reader.GetString(col);
            }

            return null;
        }
        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        private string GetExceptionText(int status)
        {
            string key;
            switch (status)
            {
                case 0:
                    return String.Empty;
                case 1:
                    key = "User not found";
                    break;
                case 2:
                    key = "Wrong password";
                    break;
                case 3:
                    key = "Wrong answer";
                    break;
                case 4:
                    key = "Invalid password";
                    break;
                case 5:
                    key = "Invalid question";
                    break;
                case 6:
                    key = "Invalid answer";
                    break;
                case 7:
                    key = "Invalid email";
                    break;
                default:
                    key = "Unknown provider error";
                    break;
            }
            return key;
        }

        /////////////////////////////////////////////////////////////////////////////
        private bool IsStatusDueToBadPassword(int status)
        {
            return (status >= 2 && status <= 6);
        }
        private const int PASSWORD_SIZE = 14;
        public virtual string GeneratePassword()
        {
            return Membership.GeneratePassword(
                      MinRequiredPasswordLength < PASSWORD_SIZE ? PASSWORD_SIZE : MinRequiredPasswordLength,
                      MinRequiredNonAlphanumericCharacters);
        }


        private OleDbParameter CreateDateTimeOleDbParameter(string parameterName, DateTime dt)
        {
            OleDbParameter p = new OleDbParameter(parameterName, OleDbType.DBTimeStamp);
            p.Direction = ParameterDirection.Input;
            p.Value = AccessConnectionHelper.RoundToSeconds(dt);
            return p;
        }

        /////////////////////////////////////////////////////////////////////////////
        /////////////////////////////////////////////////////////////////////////////
        private OleDbParameter CreateOleDbParam(string paramName, OleDbType oledbType, object objValue)
        {

            OleDbParameter param = new OleDbParameter(paramName, oledbType);

            if (objValue == null)
            {
                param.IsNullable = true;
                param.Value = DBNull.Value;
            }
            else
            {
                param.Value = objValue;
            }

            return param;
        }
    }
}
