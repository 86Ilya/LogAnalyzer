# -*- coding: utf-8 -*-

import unittest
from log_analyzer import log_analyzer
import datetime
import os


class TestLogAnalyzer(unittest.TestCase):
    def __init__(self, *args, **kwargs):
        super(TestLogAnalyzer, self).__init__(*args, **kwargs)

        self.serialized_dict = '[{"count": 1, "time_avg": 0.3900, "time_max": 0.39, "time_sum": 0.39,' \
                               ' "url": "/api/v2/banner/25019354", "time_med": 0.39, "time_perc": 74.569789675,' \
                               ' "count_perc": 50.00},{"count": 1, "time_avg": 0.1330, "time_max": 0.133,' \
                               ' "time_sum": 0.133, "url": "/api/1/photogenic_banners/list/?server_name=WIN7RB4",' \
                               ' "time_med": 0.133, "time_perc": 25.430210325, "count_perc": 50.00},]'

        self.log_content = ['1.196.116.32 -  - [29/Jun/2017:03:50:22 +0300] "GET'
                            ' /api/v2/banner/25019354 HTTP/1.1" 200 927 "-"'
                            ' "Lynx/2.8.8dev.9 libwww-FM/2.14 SSL-MM/1.4.1 GNUTLS/2.10.5"'
                            ' "-" "1498697422-2190034393-4708-9752759" "dc7161be3" 0.390',
                            '1.99.174.176 3b81f63526fa8  - [29/Jun/2017:03:50:22 +0300] "GET'
                            ' /api/1/photogenic_banners/list/?server_name=WIN7RB4 HTTP/1.1" 200 12 "-"'
                            ' "Python-urllib/2.7" "-" "1498697422-32900793-4708-9752770" "-" 0.133']

        self.top_urls = ['/api/v2/banner/25019354', '/api/1/photogenic_banners/list/?server_name=WIN7RB4']

        self.report_dict = {
            '/api/v2/banner/25019354': {'count': 1, 'time_avg': 0.39, 'time_max': 0.39, 'time_sum': 0.39,
                                          'time_med': 0.39, 'time_perc': 74.5697896749522, 'count_perc': 50.0},
            '/api/1/photogenic_banners/list/?server_name=WIN7RB4': {'count': 1, 'time_avg': 0.133,
                                                                     'time_max': 0.133, 'time_sum': 0.133,
                                                                     'time_med': 0.133,
                                                                     'time_perc': 25.430210325047803,
                                                                     'count_perc': 50.0}
            }

        self.config_from_file = {
            "REPORT_DIR": "./reports",
            "REPORT_TEMPLATE": "./report.html",
            "LOG_DIR": "./log",
            "LOGLEVEL": 40,
            "LOGFILE": "tmp.log",
            "REPORT_SIZE": 1000,
            "MAX_ERRORS_PERCENT": 1
            }

        self.log_name = None
        self.log_date = None
        self.log_type = None

    def test_get_recent_log(self):
        self.log_name, self.log_date, self.log_type = log_analyzer.get_recent_log("./logs", log_analyzer.regexprs[
            "LOG_NAME_REGEXP"])
        self.assertEquals(self.log_name, 'nginx-access-ui.log-20170720')
        self.assertEquals(self.log_date, datetime.datetime(2017, 7, 20, 0, 0))
        self.assertIsNone(self.log_type)

    def test_read_log(self):
        i = 0
        for line in log_analyzer.read_log('./logs/nginx-access-ui.log-20170720', None):
            self.assertEquals(line.strip(), self.log_content[i])
            i += 1

    def test_median(self):
        self.assertEquals(log_analyzer.median([1, 2, 3]), 2)
        self.assertEquals(log_analyzer.median([1, 2, 3, 4]), 2.5)

    def test_serialize_report_dict(self):
        self.assertEquals(
            str(log_analyzer.serialize_report_dict(self.top_urls, self.report_dict)), self.serialized_dict)

    def test_calculate_statistic(self):
        log_iter = log_analyzer.read_log('./logs/nginx-access-ui.log-20170720', None)
        top_urls, report = log_analyzer.calculate_statistic(log_iter,
                                                            r'\"[A-Z]+\s(?P<url>[\S]+)\s.+\"\s(?P<time>\S+)$', 2)
        self.assertDictEqual(self.report_dict, report)
        self.assertEquals(self.top_urls, top_urls)

    def test_generate_report(self):
        self.assertTrue(log_analyzer.generate_report('./reports/report.html', './reports/report_NEW.html',
                                                     self.serialized_dict))
        os.remove('./reports/report_NEW.html')

    def test_update_config_from_file(self):
        config = {
            "REPORT_SIZE": 1,
            "REPORT_DIR": "./reports",
            "LOG_DIR": None,
            "REPORT_TEMPLATE": None,
            "LOGFILE": None,
            "LOGLEVEL": 1,
        }
        log_analyzer.update_config_from_file("./config.cfg", config)
        self.assertDictEqual(self.config_from_file, config)


if __name__ == '__main__':
    unittest.main()
