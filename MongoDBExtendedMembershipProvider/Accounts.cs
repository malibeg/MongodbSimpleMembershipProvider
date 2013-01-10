using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace MongoDBExtendedMembershipProvider
{
    public class Base
    {
        public ObjectId Id { get; set; }
    }

    public class WebpagesMembership
    {
        [BsonId]
        public Guid Id { get; set; }
        public int UserId { get; set; }
        public string ConfirmationToken { get; set; }
        public Nullable<System.DateTime> CreateDate { get; set; }
        public Nullable<System.Boolean> IsConfirmed { get; set; }
        public Nullable<System.DateTime> LastPasswordFailureDate { get; set; }
        public string Password { get; set; }
        public Nullable<System.DateTime> PasswordChangedDate { get; set; }
        public Int32 PasswordFailuresSinceLastSuccess { get; set; }
        public System.String PasswordSalt { get; set; }
        public System.String PasswordVerificationToken { get; set; }
        public Nullable<System.DateTime> PasswordVerificationTokenExpirationDate { get; set; }
    }

    public class UserProfile
    {
        [BsonId]
        public int UserId { get; set; }
        public string UserName { get; set; }
    }

    public class WebpagesOauthToken : Base
    {
        public string Token { get; set; }
        public string Secret { get; set; }
    }

    public class WebpagesOauthMembership : Base
    {
        public string Provider { get; set; }
        public string ProviderUserId { get; set; }
        //FK
        public int UserId { get; set; }
    }
}
