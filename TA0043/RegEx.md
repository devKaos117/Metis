## E-mail
	[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}

## Username
### RegEx
	\b['"]?(usr|user|username|login)['"]?(?:\s|\t)*(?:=|:|=>|->|-)(?:\s|\t)*("(?:[^"]+)"|'(?:[^']+)'|[a-zA-Z0-9\u00C0-\u00FF\-_.!@#$%&]*)/i
### Breakdown
	\b -> define a word boundary
	['"]? -> Optionally start with quotes
	1. (usr|user|username|login) -> Field name group
	['"]? -> Optionally end with quotes
	(?:\s|\t)*(?:=|:|=>|->|-)(?:\s|\t)* -> Common field name and value separators enclosed by spaces or tabulation characters
	2. ("(?:[^"]+)"|'(?:[^']+)'|[a-zA-Z0-9\u00C0-\u00FF\-_.!@#$%&]*) -> Field value group:
		"(?:[^"]+)" -> Anything inclosed by quotes
		'(?:[^']+)' -> Anything inclosed by quotes
		[0-9a-zA-Z\u00C0-\u00FF\-_.!@#$%&]* -> A sequence of numbers, letters, accented or not, and special characters
	/i -> Case insensitive flag
### Test
	{"username": "admin_service"}
	user: deploy_user
	<identity><login>sys_internal</login></identity>
	user-name = "security_audit"
	DB_USER=prod_db_admin
	login = operator_01
	app.auth.user.name=dev_tester
	Host production\n  User ubuntu
	mongodb://svc_account:P@ssword123@localhost:27017
	User ID=sa;Password=secret;
	INSERT INTO users (username, role) VALUES ('alice_wonder', 'admin');
	config = {"login": "backend_dev"}
	export USER="root_access"
	const authUser = 'web_client_user';
	- Remember to login as **jdoe_admin** for the weekly sync.
	id,username,email\n1,mark_smith,msmith@corp.local
	Apr  5 12:51:06 login[123]: Accepted password for git_user from 192.168.1.5
	dn: uid=it_manager,ou=people,dc=example,dc=com
	(&(objectClass=user)(sAMAccountName=it_security_scan))
	web_manager:$apr1$7j12fa/s
	username net_admin privilege 15 password 7 0822
### Notes
- Text note
- JSON
- XML
- YAML
- TOML
- `.env`
- Java `.properties`
- URI
- SQL
- DBMS connection string
- Bash
- Powershell
- PHP
- ASP.NET
- Python
- JavaScript
- TypeScript
- Markdown
- CSV
- Log
- LDAP/AD search
- LDIF
- Cisco config
- Hash
- HTTP headers

## URI
### RegEx
	(?:([a-zA-Z][a-zA-Z0-9+.-]*):(?://)?)?(?:([^\s/:]+:(?:[^\s/@]+)?)@)?([^\s/]+)(?:/([^\s?#]*))?(?:\?([^\s#]*))?(?:#([^\s]*))?

### Breakdown
	1. (?:([a-zA-Z][a-zA-Z0-9+.-]*):(?://)?)? -> schema optional group
	2. (?:([^\n\t /:]+:(?:[^\n\t /@]+)?)@)? -> userinfo optional group
	3. ([^\n\t /]+) -> host group
	4. (?:/([^\n\t ?#]*))? -> path optional group
	5. (?:\?([^\n\t #]*))? -> query optional group
	6. (?:#([^\n\t ]*))? -> fragment optional group

### Test
	https://usr:pwd@www.google.com/search?q=query#fragment
	ftp://ftp.is.co.za/rfc/rfc1808.txt
	http://www.ietf.org/rfc/rfc2396.txt
	ldap://[2001:db8::7]/c=GB?objectClass?one
	telnet://192.0.2.16:80/
	mailto:John.Doe@example.com
	news:comp.infosystems.www.servers.unix
	tel:+1-816-555-1212
	urn:oasis:names:specification:docbook:dtd:xml:4.1.2

### Notes
Too many optional capturing groups, ends up matching any word

### RegEx
	\b(?:(?:[a-zA-Z][a-zA-Z0-9+.-]+:(?://)?)|(?:www\.)|(?:[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}))(?:[^\s/:]+(?::[^\s/@]+)?@)?([^\s/"'<>]+)(?:/([^\s"'<>?#]*))?(?:\?([^\s"'<>#]*))?(?:#([^\s"'<>]*))?

### Breakdown
### Test
### Notes

## IP
### RegEx
	\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b

### Breakdown
### Test
### Notes
### RegEx
	\b(?:[a-fA-F0-9]{1,4}:){1,7}:?[a-fA-F0-9]{1,4}\b

### Breakdown
### Test
### Notes
### RegEx
	\b(?:(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}|(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}|(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}|(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:(?:(?::[0-9a-fA-F]{1,4}){1,6})|:(?:(?::[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(?::[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(?:ffff(?::0{1,4}){0,1}:){0,1}(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])|(?:[0-9a-fA-F]{1,4}:){1,4}:(?:(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3}(?:25[0-5]|(?:2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\b

### Breakdown
### Test
### Notes

## Version String
### RegEx
	(\d+(?:(?:\.\d+){0,2})(?:(?:\.\*)|(?:\.\d+))?)((?:[a-zA-Z](?:\d+)?|\*)|(?:(?:-|_|\+)(?:[a-zA-Z0-9_\-\+]+|\*)))?

### Breakdown
	1. (\d+(?:(?:\.\d+){0,2})(?:(?:\.\*)|(?:\.\d+))?) -> Version numbers group:
		\d+ -> Starts with one or more digits (major version)
		(?:(?:\.\d+){0,2}) -> Followed by 0-2 occurrences of dot + digits (minor.patch)
		(?:(?:\.\*)|(?:\.\d+))? -> Optional final component that can be .* or .digits (build)

	2. ((?:[a-zA-Z](?:\d+)?|\*)|(?:(?:-|_|\+)(?:[a-zA-Z0-9_\-\+]+|\*)))? -> Optional suffix group:
		(?:[a-zA-Z](?:\d+)?|\*) -> Single letter suffix (followed or not by numbers) or wildcard
		OR
		(?:(?:-|_|\+)(?:[a-zA-Z0-9_\-\+]+|\*)) -> Delimiter followed by alphanumeric suffix or wildcard

### Test
### Notes

