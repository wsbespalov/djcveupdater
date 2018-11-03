# Generated by Django 2.1 on 2018-11-02 15:13

import django.contrib.postgres.fields
from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='VULNERABILITY_CAPEC',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('capec_id', models.TextField(default='')),
                ('name', models.TextField(default='')),
                ('summary', models.TextField(default='')),
                ('prerequisites', models.TextField(default='')),
                ('solutions', models.TextField(default='')),
                ('related_weakness', django.contrib.postgres.fields.ArrayField(base_field=models.TextField(blank=True), default=list, size=None)),
                ('created', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'verbose_name': 'VULNERABILITY_CAPEC',
                'verbose_name_plural': 'VULNERABILITY_CAPEC',
                'ordering': ['capec_id'],
            },
        ),
        migrations.CreateModel(
            name='VULNERABILITY_CAPEC_MODIFIED',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('capec_id', models.TextField(default='')),
                ('name', models.TextField(default='')),
                ('summary', models.TextField(default='')),
                ('prerequisites', models.TextField(default='')),
                ('solutions', models.TextField(default='')),
                ('related_weakness', django.contrib.postgres.fields.ArrayField(base_field=models.TextField(blank=True), default=list, size=None)),
                ('created', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'verbose_name': 'VULNERABILITY_CAPEC_MODIFIED',
                'verbose_name_plural': 'VULNERABILITY_CAPEC_MODIFIED',
                'ordering': ['capec_id'],
            },
        ),
        migrations.CreateModel(
            name='VULNERABILITY_CAPEC_NEW',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('capec_id', models.TextField(default='')),
                ('name', models.TextField(default='')),
                ('summary', models.TextField(default='')),
                ('prerequisites', models.TextField(default='')),
                ('solutions', models.TextField(default='')),
                ('related_weakness', django.contrib.postgres.fields.ArrayField(base_field=models.TextField(blank=True), default=list, size=None)),
                ('created', models.DateTimeField(default=django.utils.timezone.now)),
            ],
            options={
                'verbose_name': 'VULNERABILITY_CAPEC_NEW',
                'verbose_name_plural': 'VULNERABILITY_CAPEC_NEW',
                'ordering': ['capec_id'],
            },
        ),
    ]