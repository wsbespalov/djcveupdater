### Restore dropped table
1. Delete migrations folder.
2. Drop row with app_name in django_migrations table
3. Run ```./manage.py makemigrations app_name```
4. Run ```./manage.py migrate```

### Defer
Use ```Entry.objects.defer("headline", "body")``` instead complex objects (define set of returned columns)

### Only
Use ```Person.objects.only("name")``` to prevent object fields

### select_for_update()
Use ```select_for_update()``` to lock object while updating

```
from django.db import transaction

entries = Entry.objects.select_for_update().filter(author=request.user)
with transaction.atomic():
    for entry in entries:
```

### select_related()
Use ```select_related()``` with queryset

```
from django.utils import timezone

# Find all the blogs with entries scheduled to be published in the future.
blogs = set()

for e in Entry.objects.filter(pub_date__gt=timezone.now()).select_related('blog'):
    # Without select_related(), this would make a database query for each
    # loop iteration in order to fetch the related blog for each entry.
    blogs.add(e.blog)
```

[https://docs.djangoproject.com/en/2.1/ref/models/querysets/#django.db.models.query.QuerySet.select_related]

