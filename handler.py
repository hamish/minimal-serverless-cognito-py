import json
import boto3
import json
import datetime
import pprint
from time import mktime
import boto3
import botocore
import urlparse

# class MyEncoder(json.JSONEncoder):
#     def default(self, obj):
#         if isinstance(obj, datetime.datetime):
#             return int(mktime(obj.timetuple()))
#         return json.JSONEncoder.default(self, obj)
pp = pprint.PrettyPrinter(indent=4)
client_cognito_idp = boto3.client('cognito-idp')

def get_html(title, body, event, context):
    CookieString = event.get('headers', {}).get('Cookie',None)
    Username=''
    if CookieString:
        cookiestmp = urlparse.parse_qsl(CookieString)
        cookies= get_dist_from_parset_vars(cookiestmp)
        AccessToken = cookies.get('AccessToken')
        print AccessToken
        if AccessToken:
            user = client_cognito_idp.get_user(
               AccessToken=AccessToken
            )
            Username = user.get('Username')
    html = '''<h2>%s</h2>
    %s
    <hr />
    <a href="home">Home</a>
    | <a href="secure">Secure</a>
    | <a href="signup">Signup</a>
    | <a href="verify">Verify</a>
    | <a href="login">Login</a>
    | <a href="logout">Logout</a>
    | <a href="setup">Setup</a>
    <hr />
    Username: %s
    <hr />
    <h3>Event</h3>
    <pre>%s</pre>
    <hr />
    <h3>Context</h3>
    <pre>%s</pre>
    ''' % (title, body, Username, pp.pformat(event), pp.pformat(vars(context)))

    return html
def get_redirect(loc, html="", cookie=None):
    response = {
        "statusCode": 302,
        "headers": {
            "Location": loc
        },
        "body": html
    } 
    if cookie:
        response['headers']['Set-Cookie'] = cookie
    return response
def get_response(html, cookie=None):
    response = {
        "statusCode": 200,
        "headers": {
            "Content-Type": "text/html"
        },
        "body": html
    };
    if cookie:
        response['headers']['Set-Cookie'] = cookie
    return response    

def get_dist_from_parset_vars(params):
    d = {}
    for p in params:
        d[p[0]] = p[1]
    return d

def get_post_vars(event):
    params = urlparse.parse_qsl(event.get('body', ''))
    return get_dist_from_parset_vars(params)

# {   u'AllowUnauthenticatedIdentities': True,
#     u'DeveloperProviderName': u'currie.cognito.test',
#     u'IdentityPoolId': u'ap-southeast-2:a4741947-d7ee-4acd-9eff-71cd3a180f15',
#     u'IdentityPoolName': u'test',
#     'ResponseMetadata': {   'HTTPHeaders': {   'connection': 'keep-alive',
#                                                'content-length': '182',
#                                                'content-type': 'application/x-amz-json-1.1',
#                                                'date': 'Fri, 06 Jan 2017 12:39:06 GMT',
#                                                'x-amzn-requestid': '1ce96555-d40d-11e6-8641-ebebb840206c'},
#                             'HTTPStatusCode': 200,
#                             'RequestId': '1ce96555-d40d-11e6-8641-ebebb840206c',
#                             'RetryAttempts': 0}}


def setup(event, context):
    client = boto3.client('cognito-identity')
    response = client.create_identity_pool(
        IdentityPoolName='test',
        AllowUnauthenticatedIdentities=True,
        # SupportedLoginProviders={
        #     'string': 'string'
        # },
        DeveloperProviderName='currie.cognito.test',
        # OpenIdConnectProviderARNs=[
        #     'string',
        # ],
        # CognitoIdentityProviders=[
        #     {
        #         'ProviderName': 'string',
        #         'ClientId': 'string'
        #     },
        # ],
        # SamlProviderARNs=[
        #     'string',
        # ]
    )

    body = "Setup Response: <pre>%s</pre>" % (pp.pformat(response))
    title="Setup"
    html = get_html(title, body, event, context)
    return get_response(html)

def logout(event, context):
    return get_redirect("home", cookie="AccessToken=deleted; expires=Thu, 01 Jan 1970 00:00:00 GMT")
def login(event, context):

    body = '''<form method="post">
    username: <input type="text" name="username" /><br />
    password: <input type="password" name="password" /><br />
    <input type="submit" />
    </form><hr />''' 

    title="login"
    html = get_html(title, body, event, context)
    return get_response(html)
def loginPost(event, context):
    # client = boto3.client('cognito-idp')
    params = get_post_vars(event)
    cookie=None
    try:
        response = client_cognito_idp.admin_initiate_auth(
            UserPoolId='ap-southeast-2_zwX4onaIH',
            ClientId='6q8o5n0p7evo7uuvejl1i88v5s',
            # AuthFlow='USER_SRP_AUTH'|'REFRESH_TOKEN_AUTH'|'REFRESH_TOKEN'|'CUSTOM_AUTH'|'ADMIN_NO_SRP_AUTH',
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': params.get('username'),
                'PASSWORD': params.get('password'),
            },
            # ClientMetadata={
            #     'string': 'string'
            # }
        )
        token = response.get('AuthenticationResult',{}).get('AccessToken')
        cookie="AccessToken=%s" % token
    except botocore.exceptions.ClientError as e:
        if e.response['Error']['Code'] == 'NotAuthorizedException':
            return get_redirect("login")
        raise
    # response = client.initiate_auth(
    #     AuthFlow='ADMIN_NO_SRP_AUTH',
    #     # AuthFlow='USER_SRP_AUTH'|'REFRESH_TOKEN_AUTH'|'REFRESH_TOKEN'|'CUSTOM_AUTH'|'ADMIN_NO_SRP_AUTH',
    #     AuthParameters={
    #         'USERNAME': params.get('username'),
    #         'PASSWORD': params.get('password'),
    #     },
    #     # ClientMetadata={
    #     #     'string': 'string'
    #     # },
    #     ClientId='6q8o5n0p7evo7uuvejl1i88v5s'
    # )


    print (response)
    title="login_post"
    body = "login response: <pre>%s</pre>" % (pp.pformat(response))
    html = get_html(title, body, event, context)
    return get_response(html, cookie=cookie)

def verify(event, context):
    b3v = boto3.__version__
    body = '''<form method="post">
    Username: <input type="text" name="username" /> <br />
    Code: <input type="text" name="code" /><br />
    <input type="submit" />
    </form>'''

    title="Verify"
    html = get_html(title, body, event, context)
    return get_response(html)
def verifyPost(event, context):
    # client = boto3.client('cognito-idp')
    params = get_post_vars(event)

    response = client_cognito_idp.confirm_sign_up(
        ClientId='6q8o5n0p7evo7uuvejl1i88v5s',
        # SecretHash='string',
        Username=params.get('username'),
        ConfirmationCode=params.get('code'),
        ForceAliasCreation=False
    )

    print (response)
    title="verify_post"
    body = "verify response: <pre>%s</pre>" % (pp.pformat(response))
    html = get_html(title, body, event, context)
    return get_response(html)


def signup(event, context):
    b3v = boto3.__version__
    body = '''<form method="post">
    Username: <input type="text" name="username" /> <br />
    Password: <input type="password" name="password" /><br />
    <input type="submit" />
    </form>'''

    title="Signup"
    html = get_html(title, body, event, context)
    return get_response(html)


def signupPost(event, context):
    # client = boto3.client('cognito-idp')
    params = get_post_vars(event)

    response = client_cognito_idp.sign_up(
        ClientId='6q8o5n0p7evo7uuvejl1i88v5s',
        # SecretHash='',
        Username=params.get('username'),
        Password=params.get('password'),
        UserAttributes=[
            {
                'Name': 'email',
                'Value': params.get('username')
            },
        ],
        # ValidationData=[
        #     {
        #         'Name': 'string',
        #         'Value': 'string'
        #     },
        # ]
    )
    print (response)
    title="Signup_post"
    body = "signup response: <pre>%s</pre>" % (pp.pformat(response))
    html = get_html(title, body, event, context)
    return get_response(html)

def secure(event, context):
    b3v = boto3.__version__
    body = "boto3 version  = %s " % (b3v)
    title="Secure"
    html = get_html(title, body, event, context)
    return get_response(html)

def home(event, context):
    html = get_html("Home", "home page", event, context)
    return get_response(html)


    # Use this code if you don't use the http event with the LAMBDA-PROXY integration
    """
    return {
        "message": "Go Serverless v1.0! Your function executed successfully!",
        "event": event
    }
    """
