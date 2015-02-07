import os
from celery import Celery
from django.conf import settings
from RAPID.configurations import PostgresConfig, AMQPConfig

# set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'RAPID.settings')

app = Celery('RAPID')

# Autodiscover tasks from installed Django applications
app.autodiscover_tasks(lambda: settings.INSTALLED_APPS)


# Routing class to send pivoteer tasks to appropriate queue
class PivoteerRouter(object):

    def route_for_task(self, task, *args, **kwargs):
        if task.startswith("pivoteer."):
            return {"queue": "pivoteer"}
        return None

# Update Celery instance with configurations
app.conf.update(
    BROKER_URL=AMQPConfig.url,
    CELERY_ROUTES=(PivoteerRouter(), ),
    CELERY_RESULT_BACKEND='db+postgresql://%s:%s@%s/%s' % (PostgresConfig.username,
                                                           PostgresConfig.password,
                                                           PostgresConfig.host,
                                                           PostgresConfig.db_name),
    #CELERY_TASK_RESULT_EXPIRES=86400
    #CELERY_IGNORE_RESULT=True
    #CELERY_TASK_SERIALIZER='json',
    #CELERY_RESULT_SERIALIZER='json',
    #CELERY_TIMEZONE='UTC',
)

@app.task(bind=True)
def debug_task(self):
    print('Request: {0!r}'.format(self.request))