MongodbSimpleMembershipProvider
===============================

Providers are not fully tested !!!
This is implementation of SimpleMemershipProvider and SimpleRoleProvider for MongoDB 
( by implementing abstract classes: WebMatrix.WebData.ExtendedMembershipProvider, and the standard System.Web.Security.RoleProvider) for MVC 4.0. 
Since it is made for MVC 4.0 it supports OAuth authentication.


Configuration
-------------

1. Reference dlls in jour project 
2. Add below xml to web.config:

https://gist.github.com/malibeg/4691363





Code is made thanks to:
-----------------------

http://www.mattjcowan.com/funcoding/2012/11/10/simplemembershipprovider-in-mvc4-for-mysql-oracle-and-more-with-llblgen/

And integer generator is from:
https://github.com/alexjamesbrown/MongDBIntIdGenerator
