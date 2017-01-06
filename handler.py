import json
import boto3
import json
import datetime
import pprint
from time import mktime
import boto3

import urlparse

# class MyEncoder(json.JSONEncoder):
#     def default(self, obj):
#         if isinstance(obj, datetime.datetime):
#             return int(mktime(obj.timetuple()))
#         return json.JSONEncoder.default(self, obj)
pp = pprint.PrettyPrinter(indent=4)

def get_html(title, body, event, context):
    html = '''<h2>%s</h2>
    %s
    <hr />
    <a href="home">Home</a>
    | <a href="secure">Secure</a>
    | <a href="signup">Signup</a>
    | <a href="setup">Setup</a>
    <hr />
    <h3>Event</h3>
    <pre>%s</pre>
    <hr />
    <h3>Context</h3>
    <pre>%s</pre>
    ''' % (title, body, pp.pformat(event), pp.pformat(vars(context)))

    return html
def get_response(html):
    response = {
        "statusCode": 200,
        "headers": {
            "Content-Type": "text/html"
        },
        "body": html
    };
    return response    

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

def signup(event, context):
    b3v = boto3.__version__
    body = '''<form method="post">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <input type="submit" />
    </form>'''

    title="Signup"
    html = get_html(title, body, event, context)
    return get_response(html)

def get_post_vars(event):
    params = urlparse.parse_qsl(event.get('body', ''))
    d = {}
    for p in params:
        d[p[0]] = p[1]
    return d

def signupPost(event, context):
    client = boto3.client('cognito-idp')
    params = get_post_vars(event)

    response = client.sign_up(
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
