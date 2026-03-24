# Generated manually for NEW_DEVICE_LOGIN audit action

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0011_alter_auditevent_action_alter_user_phone_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='auditevent',
            name='action',
            field=models.CharField(
                choices=[
                    ('LOGIN_SUCCESS', 'Login success'),
                    ('LOGIN_FAILED', 'Login failed'),
                    ('NEW_DEVICE_LOGIN', 'New device login (employee)'),
                    ('USER_APPROVED', 'User approved (can log in)'),
                    ('ORDER_CREATED', 'Order created'),
                    ('ORDER_VIEWED', 'Order viewed'),
                    ('ORDER_DOWNLOADED', 'Order PDF downloaded'),
                    ('PROGRESS_UPLOADED', 'Progress uploaded'),
                    ('USER_DOCUMENT_UPLOADED', 'User document uploaded'),
                    ('ORDER_DELETED', 'Order deleted'),
                    ('ACCOUNT_DELETED_FAILED_LOGINS', 'Account deleted (3 failed logins)'),
                    ('PROFILE_UPDATED', 'Profile updated'),
                ],
                max_length=64,
            ),
        ),
    ]
