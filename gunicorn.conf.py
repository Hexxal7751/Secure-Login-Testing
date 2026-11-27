"""Gunicorn settings (picked up automatically because the file is named gunicorn.conf.py).

The default (one worker, one thread) means a single slow request, such as sending an email, makes
every other visitor wait. Several threads let the site answer other people in the meantime.
"""
import os

worker_class = "gthread"
workers = int(os.getenv("WEB_CONCURRENCY", "2"))
threads = int(os.getenv("WEB_THREADS", "4"))
timeout = 60
graceful_timeout = 30
keepalive = 5
preload_app = True          # load the app once, then fork: starts faster and uses less memory
accesslog = "-"
errorlog = "-"
