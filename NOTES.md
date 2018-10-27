### Restore dropped table
1. Delete migrations folder.
2. Drop row with app_name in django_migrations table
3. Run ```./manage.py makemigrations app_name```
4. Run ```./manage.py migrate```