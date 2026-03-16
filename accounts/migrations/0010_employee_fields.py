from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('accounts', '0009_add_user_phone'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='date_of_birth',
            field=models.DateField(blank=True, help_text='Date of birth.', null=True),
        ),
        migrations.AddField(
            model_name='user',
            name='employee_number',
            field=models.CharField(
                blank=True,
                help_text='Employee number; used as username for employee login.',
                max_length=64,
                null=True,
                unique=True,
            ),
        ),
    ]
