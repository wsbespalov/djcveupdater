# Generated by Django 2.1 on 2018-11-06 11:46

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('updater_npm', '0012_auto_20181105_1630'),
    ]

    operations = [
        migrations.AddField(
            model_name='status_npm',
            name='name',
            field=models.TextField(default=''),
        ),
    ]
