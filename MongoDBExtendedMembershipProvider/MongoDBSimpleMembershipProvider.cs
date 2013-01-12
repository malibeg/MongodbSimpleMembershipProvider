using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Configuration.Provider;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Helpers;
using System.Web.Profile;
using System.Web.Security;
using MongoDB.Bson;
using MongoDB.Bson.Serialization;
using MongoDB.Driver;
using MongoDB.Driver.Builders;
using WebMatrix.WebData;

namespace MongoDBExtendedMembershipProvider
{
    public class MongoDBSimpleMembershipProvider : ExtendedMembershipProvider
    {
        private const int TokenSizeInBytes = 0x10;

        #region Constructor(s)
        private MongoDatabase mongoDB;

        public MongoDBSimpleMembershipProvider()
        {
        }

        //public ExtendedAdapterMembershipProvider(IDataAccessAdapterFactory dataAccessAdapterFactory)
        //{
        //    this.adapterFactory = dataAccessAdapterFactory;
        //}
        #endregion

        #region Initialize
        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
                throw new ArgumentNullException("config");
            if (string.IsNullOrEmpty(name))
            {
                name = "ExtendedAdapterMembershipProvider";
            }
            if (string.IsNullOrEmpty(config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Adapter Extended Membership Provider");
            }
            base.Initialize(name, config);

            ApplicationName = GetValueOrDefault(config, "applicationName", o => o.ToString(), "MySampleApp");
            
            // MongoDB setup
            this.ConnectionStringName = GetValueOrDefault(config, "connectionString", o => o.ToString(), string.Empty);
            this.mongoDB = MongoServer.Create(config["connectionString"] ?? "mongodb://localhost").GetDatabase(config["database"] ?? "nadjiba");
            mongoDB.SetProfilingLevel(ProfilingLevel.All);
            // set id autoincrement generator
            BsonClassMap.RegisterClassMap<UserProfile>(cm =>
            {
                cm.AutoMap();
                cm.IdMemberMap.SetIdGenerator(new IntIdGenerator());
            });
            var userProfile = mongoDB.GetCollection("UserProfile");
            userProfile.EnsureIndex("UserName");
            var webpagesMembership = mongoDB.GetCollection("WebpagesMembership");
            webpagesMembership.EnsureIndex("UserId");

            // membership settings
            this.EnablePasswordRetrievalInternal = GetValueOrDefault(config, "enablePasswordRetrieval", Convert.ToBoolean, false);
            this.EnablePasswordResetInternal = GetValueOrDefault(config, "enablePasswordReset", Convert.ToBoolean, true);
            this.RequiresQuestionAndAnswerInternal = GetValueOrDefault(config, "requiresQuestionAndAnswer", Convert.ToBoolean, false);
            this.RequiresUniqueEmailInternal = GetValueOrDefault(config, "requiresUniqueEmail", Convert.ToBoolean, true);
            this.MaxInvalidPasswordAttemptsInternal = GetValueOrDefault(config, "maxInvalidPasswordAttempts", Convert.ToInt32, 3);
            this.PasswordAttemptWindowInternal = GetValueOrDefault(config, "passwordAttemptWindow", Convert.ToInt32, 10);
            this.PasswordFormatInternal = GetValueOrDefault(config, "passwordFormat", o =>
            {
                MembershipPasswordFormat format;
                return Enum.TryParse(o.ToString(), true, out format) ? format : MembershipPasswordFormat.Hashed;
            }, MembershipPasswordFormat.Hashed);
            this.MinRequiredPasswordLengthInternal = GetValueOrDefault(config, "minRequiredPasswordLength", Convert.ToInt32, 6);
            this.MinRequiredNonAlphanumericCharactersInternal = GetValueOrDefault(config, "minRequiredNonalphanumericCharacters",
                                                                          Convert.ToInt32, 1);
            this.PasswordStrengthRegularExpressionInternal = GetValueOrDefault(config, "passwordStrengthRegularExpression",
                                                                       o => o.ToString(), string.Empty);
            this.HashAlgorithmType = GetValueOrDefault(config, "hashAlgorithmType", o => o.ToString(), "SHA1");

            config.Remove("name");
            config.Remove("description");
            config.Remove("applicationName");
            config.Remove("connectionString");
            config.Remove("enablePasswordRetrieval");
            config.Remove("enablePasswordReset");
            config.Remove("requiresQuestionAndAnswer");
            config.Remove("requiresUniqueEmail");
            config.Remove("maxInvalidPasswordAttempts");
            config.Remove("passwordAttemptWindow");
            config.Remove("passwordFormat");
            config.Remove("minRequiredPasswordLength");
            config.Remove("minRequiredNonalphanumericCharacters");
            config.Remove("passwordStrengthRegularExpression");
            config.Remove("hashAlgorithmType");

            if (config.Count <= 0)
                return;
            var key = config.GetKey(0);
            if (string.IsNullOrEmpty(key))
                return;

            throw new ProviderException(string.Format(CultureInfo.CurrentCulture,
                                                      "The membership provider does not recognize the configuration attribute {0}.",
                                                      key));
        }

        public string ConnectionStringName { get; set; }
        public string HashAlgorithmType { get; set; }

        #endregion

        #region Abstract Property Overrides
        public override string ApplicationName { get; set; }

        public override bool EnablePasswordReset
        {
            get { return EnablePasswordResetInternal; }
        }
        private bool EnablePasswordResetInternal { get; set; }

        public override bool EnablePasswordRetrieval
        {
            get { return EnablePasswordRetrievalInternal; }
        }
        private bool EnablePasswordRetrievalInternal { get; set; }

        public override int MaxInvalidPasswordAttempts
        {
            get { return MaxInvalidPasswordAttemptsInternal; }
        }
        private int MaxInvalidPasswordAttemptsInternal { get; set; }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return MinRequiredNonAlphanumericCharactersInternal; }
        }
        private int MinRequiredNonAlphanumericCharactersInternal { get; set; }

        public override int MinRequiredPasswordLength
        {
            get { return MinRequiredPasswordLengthInternal; }
        }
        private int MinRequiredPasswordLengthInternal { get; set; }

        public override int PasswordAttemptWindow
        {
            get { return PasswordAttemptWindowInternal; }
        }
        private int PasswordAttemptWindowInternal { get; set; }

        public override MembershipPasswordFormat PasswordFormat
        {
            get { return PasswordFormatInternal; }
        }
        private MembershipPasswordFormat PasswordFormatInternal { get; set; }

        public override string PasswordStrengthRegularExpression
        {
            get { return PasswordStrengthRegularExpressionInternal; }
        }
        private string PasswordStrengthRegularExpressionInternal { get; set; }

        public override bool RequiresQuestionAndAnswer
        {
            get { return RequiresQuestionAndAnswerInternal; }
        }
        private bool RequiresQuestionAndAnswerInternal { get; set; }

        public override bool RequiresUniqueEmail
        {
            get { return RequiresUniqueEmailInternal; }
        }
        private bool RequiresUniqueEmailInternal { get; set; }
        #endregion

        #region Abstract Method Overrides
        private IMongoQuery GetQuery(ProfileAuthenticationOption authenticationOption, string usernameToMatch, DateTime? userInactiveSinceDate)
        {
            var query = Query.EQ("ApplicationName", this.ApplicationName);

            if (authenticationOption != ProfileAuthenticationOption.All)
            {
                query = Query.And(query, Query.EQ("IsAnonymous", authenticationOption == ProfileAuthenticationOption.Anonymous));
            }

            if (!String.IsNullOrWhiteSpace(usernameToMatch))
            {
                query = Query.And(query, Query.Matches("UserName", usernameToMatch));
            }

            if (userInactiveSinceDate.HasValue)
            {
                query = Query.And(query, Query.LTE("LastActivityDate", userInactiveSinceDate));
            }

            return query;
        }

        public override bool ConfirmAccount(string accountConfirmationToken)
        {
            var query = Query.EQ("AccountConfirmationToken", accountConfirmationToken);
            var account = this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").FindOne(query);
            if (account != null)
            {
                account.IsConfirmed = true;
                this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Save(account, WriteConcern.Acknowledged);
                return true;
            }
            return false;
        }

        public override bool ConfirmAccount(string userName, string accountConfirmationToken)
        {
            var query = Query.EQ("AccountConfirmationToken", accountConfirmationToken);
            query = Query.And(query, Query.EQ("UserName", userName));
            var account = this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").FindOne(query);
            if (account != null)
            {
                account.IsConfirmed = true;
                this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Save(account, WriteConcern.Acknowledged);
                return true;
            }
            return false;
        }


        public override string CreateUserAndAccount(string userName, string password, bool requireConfirmation, IDictionary<string, object> values)
        {

            {
                this.CreateUser(userName, values);
                return this.CreateAccount(userName, password, requireConfirmation);
            }
        }

        public override bool DeleteAccount(string userName)
        {

            {
                var user = GetUsers(new[] { userName }).FirstOrDefault();
                if (user == null)
                    return false;
                var query = Query.EQ("UserId", user.UserId);
                return this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Remove(query, WriteConcern.Acknowledged).Ok;
            }
        }

        public override string GeneratePasswordResetToken(string userName, int tokenExpirationInMinutesFromNow)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentException("Username cannot be empty", "UserName");
            }
            if (this.mongoDB != null)
            {
                bool throwException = true;
                var userId = this.VerifyUserNameHasConfirmedAccount(userName, throwException);

                var user = this.mongoDB.GetCollection<UserProfile>("UserProfile").Find(
                        Query.EQ("UserId", userId));

                var membership = this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").FindOne(
                        Query.EQ("UserId", userId));
                if (membership.PasswordVerificationTokenExpirationDate != null && membership.PasswordVerificationTokenExpirationDate.Value > DateTime.UtcNow)
                {
                    return membership.PasswordVerificationToken;
                }
                var token = GenerateToken();
                membership.PasswordVerificationToken = token;
                membership.PasswordVerificationTokenExpirationDate = DateTime.UtcNow.AddMinutes((double)tokenExpirationInMinutesFromNow);

                if (!this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Save(membership, WriteConcern.Acknowledged).Ok)
                {
                    throw new ProviderException("Unable to generate password reset token");
                }

                return token;
            }
            return string.Empty;
        }

        public override ICollection<OAuthAccountData> GetAccountsForUser(string userName)
        {
            var user = GetUsers(new[] { userName }).FirstOrDefault();
            if (user != null)
            {
                var list = new List<OAuthAccountData>();
                var oauthMems = this.mongoDB.GetCollection<WebpagesOauthMembership>("WebpagesOauthMembership").Find(
                    Query.EQ("UserId", user.UserId));
                foreach (var oauth in oauthMems)
                {
                    list.Add(new OAuthAccountData(oauth.Provider, oauth.ProviderUserId));
                }
                return list;
            }
            return new OAuthAccountData[0];
        }

        public override DateTime GetCreateDate(string userName)
        {
            var user = GetUsers(new[] { userName }).FirstOrDefault();
            var query = Query.EQ("UserId", user.UserId);
            var userMembership = this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").FindOne(query);
            if (userMembership != null && userMembership.CreateDate != null)
            {
                return userMembership.CreateDate.Value;
            }
            return DateTime.MinValue;
        }

        public override DateTime GetLastPasswordFailureDate(string userName)
        {
            var user = GetUsers(new[] { userName }).FirstOrDefault();
            var query = Query.EQ("UserId", user.UserId);
            var userMembership = this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").FindOne(query);
            if (userMembership != null && userMembership.LastPasswordFailureDate != null)
            {
                return userMembership.LastPasswordFailureDate.Value;
            }
            return DateTime.MinValue;
        }

        public override DateTime GetPasswordChangedDate(string userName)
        {
            var user = GetUsers(new[] { userName }).FirstOrDefault();
            var query = Query.EQ("UserId", user.UserId);
            var userMembership = this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").FindOne(query);
            if (userMembership != null && userMembership.PasswordChangedDate != null)
            {
                return userMembership.PasswordChangedDate.Value;
            }
            return DateTime.MinValue;
        }

        public override int GetPasswordFailuresSinceLastSuccess(string userName)
        {

            {
                var user = GetUsers(new[] { userName }).FirstOrDefault();
                if (user == null)
                {
                    throw new InvalidOperationException(string.Format("User {0} does not exist!", userName));
                }
                return GetPasswordFailuresSinceLastSuccessInternal(user.UserId);
            }
        }

        public override int GetUserIdFromPasswordResetToken(string token)
        {
            var query = Query.EQ("PasswordVerificationToken", token);
            var users = this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Find(query);
            if (users.Count() == 0)
                return -1;
            return users.First().UserId;
        }

        public override bool IsConfirmed(string userName)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentException("Username cannot be empty", "UserName");
            }

            {
                bool throwException = false;
                return (this.VerifyUserNameHasConfirmedAccount(userName, throwException) != -1);
            }
        }

        public override bool ResetPasswordWithToken(string token, string newPassword)
        {
            if (string.IsNullOrEmpty(newPassword))
            {
                throw new ArgumentException("NewPassword cannot be empty", "newPassword");
            }

            var query = Query.EQ("PasswordVerificationToken", token);
            query = Query.And(query, Query.GT("PasswordVerificationTokenExpirationDate", DateTime.UtcNow));
            var memberships = this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Find(query);

            if (memberships.Count() == 1)
            {
                var membership = memberships.First();
                var passwordSet = SetPasswordInternal(membership.UserId, newPassword);
                if (passwordSet)
                {
                    membership.PasswordVerificationToken = null;
                    membership.PasswordVerificationTokenExpirationDate = null;
                    if (!this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Save(membership).Ok)
                        throw new ProviderException("Unable to reset password with token!");
                }
                return passwordSet;
            }

            return false;
        }

        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException("Username cannot be empty", "UserName");
            }
            if (string.IsNullOrEmpty(oldPassword))
            {
                throw new ArgumentException("OldPassword cannot be empty", "oldPassword");
            }
            if (string.IsNullOrEmpty(newPassword))
            {
                throw new ArgumentException("NewPassword cannot be empty", "newPassword");
            }

            {
                var user = GetUsers(new[] { username }).FirstOrDefault();
                if (user == null)
                {
                    return false;
                }
                if (!this.CheckPassword(user.UserId, oldPassword))
                {
                    return false;
                }
                return SetPasswordInternal(user.UserId, newPassword);
            }
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            var user = GetUsers(new[] { username }).FirstOrDefault();
            if (user == null)
            {
                return false;
            }

            if (deleteAllRelatedData)
            {
                //TODO: delete some stuff here
            }

            var query = Query.EQ("UserId", user.UserId);
            var res = this.mongoDB.GetCollection<WebpagesOauthMembership>("WebpagesOauthMembership").Remove(query, WriteConcern.Acknowledged).Ok;
            res &= this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Remove(query, WriteConcern.Acknowledged).Ok;
            // TODO what if above fails
            return this.mongoDB.GetCollection<UserProfile>("UserProfile").Remove(query, WriteConcern.Acknowledged).Ok;
        }

        public override System.Web.Security.MembershipUser GetUser(string username, bool userIsOnline)
        {
            var user = GetUsers(new[] { username }).FirstOrDefault();
            if (user == null)
            {
                return null;
            }
            return new MembershipUser(Membership.Provider.Name, username, user.UserId, null, null, null, true, false, DateTime.MinValue, DateTime.MinValue, DateTime.MinValue, DateTime.MinValue, DateTime.MinValue);
        }

        public override bool ValidateUser(string username, string password)
        {
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException("Username cannot be empty", "UserName");
            }
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentException("Password cannot be empty", "Password");
            }

            {
                bool throwException = false;
                int userId = this.VerifyUserNameHasConfirmedAccount(username, throwException);
                if (userId == -1)
                {
                    return false;
                }
                return this.CheckPassword(userId, password);
            }
        }
        #endregion

        #region Required ExtendedMembershipProvider Overrides
        public override string CreateAccount(string userName, string password)
        {
            // let the base class handle this one
            return base.CreateAccount(userName, password);
        }
        public override void CreateOrUpdateOAuthAccount(string provider, string providerUserId, string userName)
        {
            if (string.IsNullOrEmpty(userName))
            {
                throw new ArgumentException("Username cannot be empty", "UserName");
            }

            {
                var user = this.GetUsers(new[] { userName }).FirstOrDefault();
                if (user == null)
                {
                    // TODO lock Inplement int generator
                    //var count = (int)this.mongoDB.GetCollection<UserProfile>("UserProfile").Count();
                    user = new UserProfile {UserName = userName };
                    this.mongoDB.GetCollection<UserProfile>("UserProfile").Insert(user, WriteConcern.Acknowledged);
                    user = this.GetUsers(new[] { userName }).FirstOrDefault();
                }
                var query = Query.EQ("Provider", provider);
                var oAuth = this.mongoDB.GetCollection<WebpagesOauthMembership>("WebpagesOauthMembership").FindOne(
                    Query.And(query, Query.EQ("ProviderUserId", providerUserId)));

                if (oAuth == null)
                {
                    oAuth = new WebpagesOauthMembership { ProviderUserId = providerUserId, Provider = provider, UserId = user.UserId };
                    if (!this.mongoDB.GetCollection<WebpagesOauthMembership>("WebpagesOauthMembership").Insert(oAuth, WriteConcern.Acknowledged).Ok)
                    {
                        throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
                    }
                }
                else
                {
                    oAuth.UserId = user.UserId;
                    if (!this.mongoDB.GetCollection<WebpagesOauthMembership>("WebpagesOauthMembership").Save(oAuth).Ok)
                    {
                        throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
                    }
                }
            }
        }
        public override string CreateUserAndAccount(string userName, string password)
        {
            // let the base class handle this one
            return base.CreateUserAndAccount(userName, password);
        }
        public override string CreateUserAndAccount(string userName, string password, bool requireConfirmation)
        {
            // let the base class handle this one
            return base.CreateUserAndAccount(userName, password, requireConfirmation);
        }
        public override string CreateUserAndAccount(string userName, string password, IDictionary<string, object> values)
        {
            // let the base class handle this one
            return base.CreateUserAndAccount(userName, password, values);
        }

        public override void DeleteOAuthAccount(string provider, string providerUserId)
        {
            var query = Query.EQ("ProviderUserId", providerUserId);
            var res = this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Remove(
                Query.And(query, Query.EQ("Provider", provider)), WriteConcern.Acknowledged);

            if (!res.Ok)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
            }
        }

        public override void DeleteOAuthToken(string token)
        {
            this.mongoDB.GetCollection<WebpagesOauthToken>("WebpagesOauthToken").Remove(
                                    Query.EQ("Token", token), WriteConcern.Acknowledged);
        }

        public override string GeneratePasswordResetToken(string userName)
        {
            // let the base class handle this one
            return base.GeneratePasswordResetToken(userName);
        }
        public override string GetOAuthTokenSecret(string token)
        {
            var oauthToken =
                this.mongoDB.GetCollection<WebpagesOauthToken>("WebpagesOauthToken").FindOne(
                    Query.EQ("Token", token));
            if (oauthToken != null)
                return oauthToken.Secret;
            return null;
        }
        public override int GetUserIdFromOAuth(string provider, string providerUserId)
        {
            var query = Query.EQ("Provider", provider);
            var oAuthMembership = this.mongoDB.GetCollection<WebpagesOauthMembership>("WebpagesOauthMembership").FindOne(Query.And(query, Query.EQ("ProviderUserId", providerUserId)));
            if (oAuthMembership != null)
            {
                return oAuthMembership.UserId;
            }
            return -1;
        }
        public override string GetUserNameFromId(int userId)
        {
            var userProfile = this.mongoDB.GetCollection<UserProfile>("UserProfile").FindOne(Query.EQ("UserId", userId));
            if (userProfile != null)
                return userProfile.UserName;
            return null;
        }
        public override bool HasLocalAccount(int userId)
        {
            var acc = this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").FindOne(Query.EQ("UserId", userId));
            return acc != null;
        }
        public override void ReplaceOAuthRequestTokenWithAccessToken(string requestToken, string accessToken, string accessTokenSecret)
        {
            this.mongoDB.GetCollection<WebpagesOauthToken>("WebpagesOauthToken").Remove(Query.EQ("Token", requestToken), WriteConcern.Acknowledged);
            this.StoreOAuthRequestToken(accessToken, accessTokenSecret);
        }
        public override void StoreOAuthRequestToken(string requestToken, string requestTokenSecret)
        {
            var tokenEntity = this.mongoDB.GetCollection<WebpagesOauthToken>("WebpagesOauthToken").FindOne(Query.EQ("Token", requestToken));

            if (tokenEntity.Secret == requestTokenSecret)
            {
                return;
            }

            tokenEntity.Secret = requestTokenSecret;
            if (!this.mongoDB.GetCollection<WebpagesOauthToken>("WebpagesOauthToken").Save(tokenEntity).Ok)
            {
                throw new ProviderException("Unable to store OAuth token");
            }
            return;

        }
        #endregion

        #region Helper Methods

        private IEnumerable<UserProfile> GetUsers(string[] usernames)
        {
            var users = this.mongoDB.GetCollection<UserProfile>("UserProfile").Find(Query.In("UserName", new BsonArray(usernames)));
            return users;
        }

        private void CreateUser(string userName, IDictionary<string, object> values)
        {
            if (GetUsers(new[] { userName }).Count() > 0)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.DuplicateUserName);
            }

            var user = new UserProfile { UserName = userName };

            // TODO check vhat can be assigned here???? 
            if (values != null)
            {
                foreach (var value in values)
                {
                    if (value.Key.Equals("UserName", StringComparison.OrdinalIgnoreCase))
                        continue;

                    var field = user.GetType().GetProperties().SingleOrDefault(f => f.Name.Equals(value.Key, StringComparison.OrdinalIgnoreCase));
                    if (field != null)
                    {
                        user.GetType().GetProperty(field.Name).SetValue(user, value.Value);
                    }
                }
            }
            // TODO Implement integer id generator !!!!
            //user.UserId = (int)this.mongoDB.GetCollection<UserProfile>("UserProfile").Count();
            var res = this.mongoDB.GetCollection<UserProfile>("UserProfile").Insert(user, WriteConcern.Acknowledged);
            //TODO check why is res null withouth writeConcern???
            if (!res.Ok)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
            }
        }

        public override string CreateAccount(string userName, string password, bool requireConfirmationToken)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidPassword);
            }
            string hashedPassword = Crypto.HashPassword(password);
            if (hashedPassword.Length > 0x80)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidPassword);
            }
            if (string.IsNullOrEmpty(userName))
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidUserName);
            }

            var user = GetUsers(new[] { userName }).FirstOrDefault();
            if (user == null)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.InvalidUserName);
            }
            string token = null;
            if (requireConfirmationToken)
            {
                token = GenerateToken();
            }

            var membership = new WebpagesMembership()
            {
                //Id = new Guid()
                UserId = user.UserId,
                Password = hashedPassword,
                PasswordSalt = string.Empty,
                IsConfirmed = !requireConfirmationToken,
                ConfirmationToken = token,
                CreateDate = DateTime.UtcNow,
                PasswordChangedDate = DateTime.UtcNow,
                PasswordFailuresSinceLastSuccess = 0
            };

            var res = this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Insert(membership,
                                                                                                  WriteConcern.
                                                                                                      Acknowledged);
            if (!res.Ok)
            {
                throw new MembershipCreateUserException(MembershipCreateStatus.ProviderError);
            }
            return token;
        }

        private bool SetPasswordInternal(int userId, string newPassword)
        {
            var hashedPassword = Crypto.HashPassword(newPassword);
            if (hashedPassword.Length > 0x80)
            {
                throw new ArgumentException("Password is too long!");
            }

            var res = mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Update(Query.EQ("UserId", userId),
                                                                                       Update.Set("Password", hashedPassword).Set(
                                                                                           "PasswordSalt", string.Empty).Set(
                                                                                           "PasswordChangedDate", DateTime.Now), WriteConcern.Acknowledged);
            return !res.HasLastErrorMessage;
        }

        private bool CheckPassword(int userId, string password)
        {
            var hashedPassword = this.GetHashedPassword(userId);
            var matches = (hashedPassword != null) && Crypto.VerifyHashedPassword(hashedPassword, password);
            if (matches)
            {
                mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Update(Query.EQ("UserId", userId),
                                                                                       Update.Set(
                                                                                           "PasswordFailuresSinceLastSuccess",
                                                                                           0));
                return matches;
            }
            int passwordFailuresSinceLastSuccess = GetPasswordFailuresSinceLastSuccessInternal(userId);
            if (passwordFailuresSinceLastSuccess != -1)
            {
                mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Update(Query.EQ("UserId", userId),
                                                                                       Update.Set(
                                                                                           "PasswordFailuresSinceLastSuccess",
                                                                                           passwordFailuresSinceLastSuccess + 1).Set("LastPasswordFailureDate", DateTime.Now));
            }
            return matches;
        }

        private int GetPasswordFailuresSinceLastSuccessInternal(int userId)
        {
            var membership = mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").FindOne(Query.EQ("UserId", userId));
            if (membership == null)
                return -1;
            return membership.PasswordFailuresSinceLastSuccess;
        }

        private string GetHashedPassword(int userId)
        {
            var membership = mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").FindOne(Query.EQ("UserId", userId));
            if (membership == null)
                return null;
            return membership.Password;
        }

        private static T GetValueOrDefault<T>(NameValueCollection nvc, string key, Func<object, T> converter, T defaultIfNull)
        {
            var val = nvc[key];

            if (val == null)
                return defaultIfNull;

            try
            {
                return converter(val);
            }
            catch
            {
                return defaultIfNull;
            }
        }

        private string GenerateToken()
        {
            using (var provider = new RNGCryptoServiceProvider())
            {
                return GenerateToken(provider);
            }
        }

        internal static string GenerateToken(RandomNumberGenerator generator)
        {
            var data = new byte[0x10];
            generator.GetBytes(data);
            return HttpServerUtility.UrlTokenEncode(data);
        }

        private int VerifyUserNameHasConfirmedAccount(string username, bool throwException)
        {
            var user = GetUsers(new[] { username }).FirstOrDefault();
            if (user == null)
            {
                if (throwException)
                {
                    throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "User {0} does not exist!", new object[] { username }));
                }
                return -1;
            }

            var query = Query.EQ("UserId", user.UserId);
            query = Query.And(query, Query.EQ("IsConfirmed", true));
            var count = this.mongoDB.GetCollection<WebpagesMembership>("WebpagesMembership").Count(query);
            if (count != 0)
            {
                return user.UserId;
            }
            if (throwException)
            {
                throw new InvalidOperationException(string.Format(CultureInfo.CurrentCulture, "User {0} does not exist!", new object[] { username }));
            }
            return -1;
        }
        #endregion

        #region Unsupported methods in the SimpleMembershipProvider model

        public override System.Web.Security.MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out System.Web.Security.MembershipCreateStatus status)
        {
            throw new NotSupportedException();
        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            throw new NotSupportedException();
        }

        public override System.Web.Security.MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override System.Web.Security.MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override System.Web.Security.MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            throw new NotSupportedException();
        }

        public override int GetNumberOfUsersOnline()
        {
            throw new NotSupportedException();
        }

        public override string GetPassword(string username, string answer)
        {
            throw new NotSupportedException();
        }

        public override System.Web.Security.MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            throw new NotSupportedException();
        }

        public override string GetUserNameByEmail(string email)
        {
            throw new NotSupportedException();
        }

        public override string ResetPassword(string username, string answer)
        {
            throw new NotSupportedException();
        }

        public override bool UnlockUser(string userName)
        {
            throw new NotSupportedException();
        }

        public override void UpdateUser(System.Web.Security.MembershipUser user)
        {
            throw new NotSupportedException();
        }
        #endregion
    }
}
