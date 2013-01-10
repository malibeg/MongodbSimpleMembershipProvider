using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using MongoDB.Bson.Serialization.Attributes;

namespace MongoDBExtendedMembershipProvider
{
    
    public class WebpagesRole
    {
        [BsonId]
        public int RoleId { get; set; }
        public string RoleName { get; set; }
    }

    public class WebpagesUsersInRole : Base
    {
        public int RoleId { get; set; }
        public int UserId { get; set; }
    }
}
