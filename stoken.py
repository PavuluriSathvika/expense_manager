from itsdangerous import URLSafeTimedSerializer
secret_key = 'mysecretkey123'
salt = 'email-confirm-salt'
def endata(data):
    serializer=URLSafeTimedSerializer(secret_key)
    return serializer.dumps(data,salt=salt)

def dedata(data):
    serializer=URLSafeTimedSerializer(secret_key)
    return serializer.loads(data,salt=salt)