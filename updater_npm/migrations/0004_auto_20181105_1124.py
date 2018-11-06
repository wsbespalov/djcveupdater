# Generated by Django 2.1 on 2018-11-05 08:24

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('updater_npm', '0003_auto_20181105_1123'),
    ]

    operations = [
        migrations.AddField(
            model_name='vulnerability_npm',
            name='module_name',
            field=models.TextField(default=''),
        ),
        migrations.AddField(
            model_name='vulnerability_npm',
            name='published_date',
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
    ]