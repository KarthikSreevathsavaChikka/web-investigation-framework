"""Single scheduler process; durable schedules and attempts survive restarts."""
import logging
import time
from datetime import datetime, timezone
from services.casework import CaseRepository
from services.api.routers.cases import check, Website


def tick(repo):
    for case in repo.list():
        history = repo.activity(case['id'])
        schedules = {a['payload']['url']: a['payload'] for a in history if a['kind'] == 'schedule'}
        for url, schedule in schedules.items():
            if not schedule['enabled']:
                continue
            attempts = [a for a in history if a['kind'] in {'website_check', 'website_error'} and a['payload']['url'] == url]
            if attempts and (datetime.now(timezone.utc) - datetime.fromisoformat(attempts[-1]['created_at'])).total_seconds() < schedule['interval_hours'] * 3600:
                continue
            try:
                check(case['id'], Website(url=url), repo)
            except Exception:
                logging.exception('Scheduled website check failed')


if __name__ == '__main__':
    while True:
        try:
            tick(CaseRepository())
        except Exception:
            logging.exception('Scheduler cycle failed')
        time.sleep(30)
