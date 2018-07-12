#!/bin/sh
while ! pg_isready -h $DJANGO_DATABASE_HOST -p "5432" > /dev/null 2> /dev/null; do
   echo "Waiting for DB host....."
   sleep 1
done
echo "Starting celery beat"
celery -A ekataauthserver beat -l info 
