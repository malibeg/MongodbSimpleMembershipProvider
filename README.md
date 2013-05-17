MongodbSimpleMembershipProvider
===============================

Providers are not fully tested !!!
This is implementation of SimpleMemershipProvider and SimpleRoleProvider for MongoDB 
( by implementing abstract classes: WebMatrix.WebData.ExtendedMembershipProvider, and the standard System.Web.Security.RoleProvider) for MVC 4.0. 
Since it is made for MVC 4.0 it supports OAuth authentication.


Configuration
-------------

Add dlls to jour project add these to web.config:

https://gist.github.com/malibeg/4691363

  <membership defaultProvider="MongodbSimpleMembershipProvider">
      <providers>
        <add name="MongodbSimpleMembershipProvider" type="MongoDBExtendedMembershipProvider.MongodbSimpleMembershipProvider" connectionString="mongodb://localhost:27017" enablePasswordRetrieval="false" enablePasswordReset="true" requiresQuestionAndAnswer="false" requiresUniqueEmail="true" maxInvalidPasswordAttempts="3" minRequiredPasswordLength="6" minRequiredNonalphanumericCharacters="1" passwordAttemptWindow="10" applicationName="/" />
      </providers>
  </membership>
  <roleManager enabled="true" defaultProvider="MongoDBSimpleRoleProvider">
      <providers>
        <add name="MongoDBSimpleRoleProvider" type="MongoDBExtendedMembershipProvider.MongoDBSimpleRoleProvider" connectionString="mongodb://localhost:27017" applicationName="/" />
      </providers>
  </roleManager>




Code is made thanks to:
-----------------------

http://www.mattjcowan.com/funcoding/2012/11/10/simplemembershipprovider-in-mvc4-for-mysql-oracle-and-more-with-llblgen/

And integer generator is from:
https://github.com/alexjamesbrown/MongDBIntIdGenerator
