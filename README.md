What is this?
=============
<code>mod\_spnego</code> enables the usage of Kerberos to authenticate
users of a website running on the Apache HTTP Server (httpd) on **Windows**.
The authenticated user is then available in the server variable
<code>AUTH_USER</code>.

Installation
============
Just copy the binary <code>mod\_spnego.so</code> to the modules directory
of the Apache installtion and add it to the modules list in
<code>httpd.conf</code>:

	LoadModule spnego_module modules/mod\_spnego.so

To enable it on a site or directory, add the following directives to it:

	<Directory "dir">
		AuthName "Windows Authentication"
		Require valid-user

		AuthType SPNEGO
		Krb5ServiceName HTTP
		Krb5RemoveDomain 1
	</Directory>
	
You might need to install the Visual C++ Runtime Libraries if they're not
already there.

Parameters
==========

*   Krb5ServiceName: the Kerberos service name(s), separated with a
    single whitespace
*   Krb5RemoveDomain: 0 to NOT strip the domain name from the user's
    login, any other number to strip it.
*   Krb5AuthEachReq: 0 for shared authentication, any other number to
    authenticate each request
*   Krb5AuthorizeFlag: checks if user matches list given in httpd.conf

The last two are untested. Use at your own risk.

Build
=====
The project was created using Visual Studio 2012 and you'll also need
Apache 2.2 installed. The project assumes
<code>C:\Program Files (x86)\Apache Software Foundation\Apache2.2</code>
as the installation directory.

Limitations
===========
The version available here has some limitations compared to the original
version:

*   Windows only
*   Apache >= 2.2 only

Contrary to the original it works reliable under high load conditions,
but no warranty whatsoever is made that it is fit for any purpose.

**Use it at your own risk!**

Credits
=======
The original version of this library was written by Frank Balluffi and Markus
Moeller. It is available at <http://sourceforge.net/projects/modgssapache>.
