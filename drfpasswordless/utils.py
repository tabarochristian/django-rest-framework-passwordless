# utils.py
import logging
import os
import random
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied, ValueError
from django.core.mail import send_mail
from django.template import loader
from django.utils import timezone
from django.db import transaction
from rest_framework.authtoken.models import Token
from drfpasswordless.models import CallbackToken, generate_numeric_token
from drfpasswordless.settings import api_settings

logger = logging.getLogger(__name__)
User = get_user_model()

# Valid alias types for validation
VALID_ALIAS_TYPES = {'EMAIL', 'MOBILE', 'CALL'}

def authenticate_by_token(callback_token):
    """
    Authenticates a user using a callback token.
    Returns the user if valid, None otherwise.
    """
    if not callback_token or not isinstance(callback_token, str):
        logger.warning("Authentication failed: Invalid or empty callback token")
        return None

    try:
        token = CallbackToken.objects.select_related('user').get(
            key=callback_token,
            is_active=True,
            type=CallbackToken.TOKEN_TYPE_AUTH
        )
        with transaction.atomic():
            token.is_active = False  # Mark token as used
            token.save()
        logger.info(f"Authenticated user {token.user.id} with token {callback_token}")
        return token.user

    except CallbackToken.DoesNotExist:
        logger.info(f"Authentication failed: Token {callback_token} does not exist or is inactive")
        return None
    except User.DoesNotExist:
        logger.error(f"Authentication failed: User for token {callback_token} does not exist")
        return None
    except PermissionDenied:
        logger.warning(f"Authentication failed: Permission denied for token {callback_token}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error during authentication with token {callback_token}: {str(e)}")
        return None

def select_virtual_number():
    pool = api_settings.PASSWORDLESS_VIRTUAL_NUMBER_POOL
    if not pool:
        raise ValueError("No virtual number pool configured.")
    return random.choice(pool)
    
    used = CallbackToken.objects.filter(is_active=True, type=CallbackToken.TOKEN_TYPE_AUTH, to_alias_type='mobile').values_list('key', flat=True)
    available = [n for n in pool if n not in used]
    if not available:
        raise ValueError("No available virtual numbers.")
    return random.choice(available)

def create_callback_token_for_user(user, alias_type, token_type):
    """
    Creates a callback token for a user based on alias_type and token_type.
    Handles demo users with predefined tokens.
    """
    if not user or not alias_type or not token_type:
        logger.error("Token creation failed: Missing user, alias_type, or token_type")
        return None

    alias_type_lower = alias_type.lower()
    if alias_type_lower == 'call':
        to_alias_field = api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME
        to_alias_type = 'mobile'
        try:
            key = select_virtual_number()
        except ValueError as e:
            logger.error(str(e))
            return None
    else:
        alias_type_u = alias_type.upper()
        if alias_type_u not in VALID_ALIAS_TYPES:
            logger.error(f"Token creation failed: Invalid alias type {alias_type}")
            return None
        to_alias_field = getattr(api_settings, f'PASSWORDLESS_USER_{alias_type_u}_FIELD_NAME')
        to_alias_type = alias_type_lower
        key = generate_numeric_token()

    try:
        alias = str(getattr(user, to_alias_field, None))
        if not alias:
            logger.error(f"Token creation failed: No {to_alias_field} found for user {user.id}")
            return None

        with transaction.atomic():
            # Handle demo users
            if alias in api_settings.PASSWORDLESS_DEMO_USERS:
                token = CallbackToken.objects.filter(user=user, is_active=True, to_alias_type=to_alias_type).first()
                if token:
                    logger.info(f"Reusing existing token for demo user {user.id}")
                    return token
                token_key = api_settings.PASSWORDLESS_DEMO_USERS.get(alias)
                if not token_key:
                    logger.error(f"Token creation failed: Invalid demo token key for alias {alias}")
                    return None
                return CallbackToken.objects.create(
                    user=user,
                    key=token_key,
                    to_alias_type=to_alias_type,
                    to_alias=alias,
                    type=token_type
                )

            # Create new token for non-demo users
            return CallbackToken.objects.create(
                user=user,
                to_alias_type=to_alias_type,
                to_alias=alias,
                type=token_type,
                key=key
            )

    except AttributeError as e:
        logger.error(f"Invalid alias field configuration for {alias_type}: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Failed to create token for user {user.id}, alias_type {alias_type}: {str(e)}")
        return None

def validate_token_age(callback_token):
    """
    Validates if a token is within the expiration time.
    Returns True if valid, False otherwise.
    """
    if not callback_token or not isinstance(callback_token, str):
        logger.warning(f"Token validation failed: Invalid or empty token")
        return False

    try:
        token = CallbackToken.objects.select_related('user').get(
            key=callback_token,
            is_active=True
        )
        # Use stored alias for demo user check to avoid redundant fetching
        if token.to_alias in api_settings.PASSWORDLESS_DEMO_USERS:
            logger.info(f"Token {callback_token} validated for demo user {token.user.id}")
            return True

        if not hasattr(api_settings, 'PASSWORDLESS_TOKEN_EXPIRE_TIME') or api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME <= 0:
            logger.error(f"Token validation failed: Invalid or missing PASSWORDLESS_TOKEN_EXPIRE_TIME")
            return False

        seconds = (timezone.now() - token.created_at).total_seconds()
        if seconds <= api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME:
            logger.info(f"Token {callback_token} validated for user {token.user.id}")
            return True

        with transaction.atomic():
            token.is_active = False
            token.save()
        logger.info(f"Token {callback_token} expired for user {token.user.id}")
        return False

    except CallbackToken.DoesNotExist:
        logger.info(f"Token validation failed: Token {callback_token} does not exist or is inactive")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during token validation for {callback_token}: {str(e)}")
        return False

def verify_user_alias(user, token):
    """
    Marks a user's contact point (email or mobile) as verified based on token.
    Returns True if successful, False otherwise.
    """
    if not user or not token or token.to_alias_type.upper() not in VALID_ALIAS_TYPES:
        logger.error(f"Alias verification failed: Invalid user, token, or alias type {getattr(token, 'to_alias_type', None)}")
        return False

    try:
        alias_type_u = token.to_alias_type.upper()
        alias_field = getattr(api_settings, f'PASSWORDLESS_USER_{alias_type_u}_FIELD_NAME')
        verified_field = getattr(api_settings, f'PASSWORDLESS_USER_{alias_type_u}_VERIFIED_FIELD_NAME')
        user_alias = str(getattr(user, alias_field, None))

        if not user_alias:
            logger.error(f"Alias verification failed: No {token.to_alias_type.lower()} for user {user.id}")
            return False

        if token.to_alias != user_alias:
            logger.warning(f"Alias verification failed: Token alias {token.to_alias} does not match user {user.id}'s {alias_field}")
            return False

        with transaction.atomic():
            setattr(user, verified_field, True)
            user.save()
        logger.info(f"Verified {token.to_alias_type.lower()} {token.to_alias} for user {user.id}")
        return True

    except AttributeError:
        logger.error(f"Invalid configuration for alias type {token.to_alias_type}")
        return False
    except Exception as e:
        logger.error(f"Failed to verify alias for user {user.id}, type {token.to_alias_type}: {str(e)}")
        return False

def inject_template_context(context):
    """
    Injects additional context into email templates using configured processors.
    """
    try:
        updated_context = context.copy()
        if not hasattr(api_settings, 'PASSWORDLESS_CONTEXT_PROCESSORS'):
            logger.warning("No context processors configured in PASSWORDLESS_CONTEXT_PROCESSORS")
            return updated_context

        for processor in api_settings.PASSWORDLESS_CONTEXT_PROCESSORS:
            if callable(processor):
                updated_context.update(processor())
            else:
                logger.warning(f"Context processor {processor} is not callable")
        return updated_context
    except Exception as e:
        logger.error(f"Failed to inject template context: {str(e)}")
        return context

def send_email_with_callback_token(user, email_token, **kwargs):
    """
    Sends an email with a callback token to the user.
    Returns True if successful, False otherwise.
    """
    if not hasattr(api_settings, 'PASSWORDLESS_EMAIL_NOREPLY_ADDRESS') or not api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS:
        logger.error("Email sending failed: PASSWORDLESS_EMAIL_NOREPLY_ADDRESS not configured")
        return False

    if not user or not email_token or not email_token.key:
        logger.error("Email sending failed: Invalid user or token")
        return False

    try:
        email_field = getattr(api_settings, 'PASSWORDLESS_USER_EMAIL_FIELD_NAME', 'email')
        recipient_email = str(getattr(user, email_field, None))
        if not recipient_email:
            logger.error(f"Email sending failed: No email address for user {user.id}")
            return False

        email_subject = kwargs.get('email_subject', getattr(api_settings, 'PASSWORDLESS_EMAIL_SUBJECT', 'Your Login Token'))
        email_plaintext = kwargs.get('email_plaintext', getattr(api_settings, 'PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE', 'Your token is %s'))
        email_html = kwargs.get('email_html', getattr(api_settings, 'PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE_NAME', 'passwordless_default_token_email.html'))

        context = inject_template_context({'callback_token': email_token.key})
        html_message = loader.render_to_string(email_html, context)

        send_mail(
            subject=email_subject,
            message=email_plaintext % email_token.key,
            from_email=api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS,
            recipient_list=[recipient_email],
            fail_silently=False,
            html_message=html_message
        )
        logger.info(f"Sent email with token {email_token.key} to user {user.id}")
        return True

    except Exception as e:
        logger.error(f"Failed to send email to user {user.id} with token {getattr(email_token, 'key', 'unknown')}: {str(e)}")
        return False

def send_sms_with_callback_token(user, mobile_token, **kwargs):
    """
    Sends an SMS with a callback token to the user via Twilio.
    Returns True if successful or suppressed in test mode, False otherwise.
    """
    if getattr(api_settings, 'PASSWORDLESS_TEST_SUPPRESSION', False):
        if not hasattr(api_settings, 'PASSWORDLESS_MOBILE_NOREPLY_NUMBER') or not api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER:
            logger.error("SMS sending suppressed but PASSWORDLESS_MOBILE_NOREPLY_NUMBER not configured")
            return False
        logger.info(f"SMS sending suppressed for user {user.id} in test mode")
        return True

    if not hasattr(api_settings, 'PASSWORDLESS_MOBILE_NOREPLY_NUMBER') or not api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER:
        logger.error("SMS sending failed: PASSWORDLESS_MOBILE_NOREPLY_NUMBER not configured")
        return False

    if not user or not mobile_token or not mobile_token.key:
        logger.error("SMS sending failed: Invalid user or token")
        return False

    try:
        from twilio.rest import Client
        twilio_client = Client(os.environ.get('TWILIO_ACCOUNT_SID'), os.environ.get('TWILIO_AUTH_TOKEN'))
        if not twilio_client:
            logger.error("SMS sending failed: Twilio credentials not configured")
            return False

        mobile_field = getattr(api_settings, 'PASSWORDLESS_USER_MOBILE_FIELD_NAME', 'mobile')
        to_number = getattr(user, mobile_field, None)
        if not to_number:
            logger.error(f"SMS sending failed: No mobile number for user {user.id}")
            return False

        if to_number.__class__.__name__ == 'PhoneNumber':
            to_number = to_number.as_e164 if hasattr(to_number, 'as_e164') else str(to_number)

        base_string = kwargs.get('mobile_message', getattr(api_settings, 'PASSWORDLESS_MOBILE_MESSAGE', 'Your token is %s'))
        twilio_client.messages.create(
            body=base_string % mobile_token.key,
            to=str(to_number),
            from_=api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER
        )
        logger.info(f"Sent SMS with token {mobile_token.key} to user {user.id}")
        return True

    except ImportError:
        logger.error("SMS sending failed: Twilio client not installed")
        return False
    except KeyError:
        logger.error("SMS sending failed: Twilio credentials or PASSWORDLESS_MOBILE_NOREPLY_NUMBER missing")
        return False
    except Exception as e:
        logger.error(f"Failed to send SMS to user {user.id} with token {getattr(mobile_token, 'key', 'unknown')}: {str(e)}")
        return False

def send_call_with_callback_token(user, mobile_token, **kwargs):
    """
    Places a missed call to the user via Twilio using a virtual number.
    Returns True if successful or suppressed in test mode, False otherwise.
    """
    if getattr(api_settings, 'PASSWORDLESS_TEST_SUPPRESSION', False):
        logger.info(f"Missed call suppressed for user {user.id} in test mode")
        return True

    if not user or not mobile_token or not mobile_token.key:
        logger.error("Missed call failed: Invalid user or token")
        return False

    try:
        from twilio.rest import Client
        twilio_client = Client(os.environ.get('TWILIO_ACCOUNT_SID'), os.environ.get('TWILIO_AUTH_TOKEN'))
        if not twilio_client:
            logger.error("Missed call failed: Twilio credentials not configured")
            return False

        mobile_field = getattr(api_settings, 'PASSWORDLESS_USER_MOBILE_FIELD_NAME', 'mobile')
        to_number = getattr(user, mobile_field, None)
        if not to_number:
            logger.error(f"Missed call failed: No mobile number for user {user.id}")
            return False

        if to_number.__class__.__name__ == 'PhoneNumber':
            to_number = to_number.as_e164 if hasattr(to_number, 'as_e164') else str(to_number)

        twiml = '<Response><Reject reason="rejected" /></Response>'
        twilio_client.calls.create(
            twiml=twiml,
            to=str(to_number),
            from_=mobile_token.key
        )
        logger.info(f"Sent missed call from {mobile_token.key} to user {user.id}")
        return True

    except ImportError:
        logger.error("Missed call failed: Twilio client not installed")
        return False
    except KeyError:
        logger.error("Missed call failed: Twilio credentials missing")
        return False
    except Exception as e:
        logger.error(f"Failed to send missed call to user {user.id} with token {getattr(mobile_token, 'key', 'unknown')}: {str(e)}")
        return False

def create_authentication_token(user):
    """
    Creates or retrieves an authentication token for the user.
    """
    if not user:
        logger.error("Auth token creation failed: Invalid user")
        return None

    try:
        with transaction.atomic():
            token, created = Token.objects.get_or_create(user=user)
        logger.info(f"{'Created' if created else 'Retrieved'} auth token for user {user.id}")
        return token
    except Exception as e:
        logger.error(f"Failed to create auth token for user {user.id}: {str(e)}")
        return None