#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import os
import re
from datetime import datetime
import gzip
import io
from collections import defaultdict, namedtuple
import logging
import argparse
import json
from string import Template
import tempfile


# log_format ui_short '$remote_addr  $remote_user $http_x_real_ip [$time_local] "$request" '
#                     '$status $body_bytes_sent "$http_referer" '
#                     '"$http_user_agent" "$http_x_forwarded_for" "$http_X_REQUEST_ID" "$http_X_RB_USER" '
#                     '$request_time';

config = {
    "REPORT_SIZE": 1000,
    "REPORT_DIR": "./reports",
    "LOG_DIR": "./log",
    "REPORT_TEMPLATE": "./report.html",
    "LOGFILE": None,
    "LOGLEVEL": logging.INFO,
    "MAX_ERRORS_PERCENT": 1,
    "LOG_FORMAT": "%(asctime)s %(levelname).1s %(message)s",
    "LOG_DATEFMT": "%Y.%m.%d,%H:%M:%S",
}

default_cfg_file = "config.cfg"

regexprs = {
    "LOG_NAME_REGEXP": r'^nginx-access-ui\.log-(\d{8})(\.gz){0,1}$',
    "NGINX_REGEXP": r'\"[A-Z]+\s(?P<url>[\S]+)\s.+\"\s(?P<time>\S+)$',
}

NginxLog = namedtuple('NginxLog', ['name', 'date', 'extension'])


def get_recent_log(log_dir, regexp):
    """
    Ищет в директории log_dir логи согласно регулярному выражению regexp
    И возвращает самый новый, согласно дате создания
    :param str log_dir:
    :param str regexp:
    :return:
    """

    files = os.listdir(log_dir)
    logs_names_gen = match_log_name(files, regexp)
    try:
        recent_log = logs_names_gen.next()
    except StopIteration:
        return

    recent_date = recent_log[1]

    for cur_log_name, cur_date, cur_log_ext in logs_names_gen:
                if recent_date < cur_date:
                    recent_date = cur_date
                    recent_log = cur_log_name, cur_date, cur_log_ext

    # Возвращаем имя лога, дату создания, расширение файла
    return NginxLog(*recent_log)


def read_log(log_full_name, file_type):
    """
    Функция - генератор. Итерируется по лог-файлу построчно
    :param str log_full_name:
    :param str file_type:
    """

    f_open = gzip.open if file_type == '.gz' else io.open
    try:
        with f_open(log_full_name, mode='r') as log_file:
            for line in log_file:
                yield line.decode('utf-8')  # Так универсальнее
    except IOError as error:
        logging.error(u"Проблема с чтением из лог файла: {}".format(error))
        yield None


def median(lst):
    """
    Возвращает медиану !отсортированного! списка
    :param list lst:
    :return float:
    """

    n = len(lst)
    if n < 1:
            return None
    if n % 2 == 1:
            return lst[n//2]
    else:
            return sum(lst[n//2-1:n//2+1])/2.0


def serialize_report_dict(top_urls, report_dict):
    """
    Сериализует полученный словарь-отчёт согласно представленному ниже шаблону
    :param list top_urls:
    :param dict report_dict:
    :return str:
    """

    report = []

    for url in top_urls:
        statistic = report_dict[url]
        report.append(
            {
                "url": url,
                "count": statistic["count"],
                "time_avg": statistic["time_avg"],
                "time_max": statistic["time_max"],
                "time_sum": statistic["time_sum"],
                "time_med": statistic["time_med"],
                "time_perc": statistic["time_perc"],
                "count_perc": statistic["count_perc"]
            }
        )

    return json.dumps(report)


def calculate_statistic(log_iterator, nginx_regex, report_size, max_errors_percent):
    """
    Считает статистику по лог файлу. Возвращает словарь со всеми данными и топ адресов, отсортированных
    по количеству вхождений
    :param log_iterator:
    :param str nginx_regex:
    :param int report_size:
    :param float max_errors_percent:
    :return tuple:
    """

    # Регулярное выражение для извлечения url и времени обработки
    nginx_pattern = re.compile(nginx_regex)
    # Суммарное количество запросов
    all_requests_count = 0
    # Суммарное время обработки запросов
    all_requests_time = 0
    # Суммарное количество несовпадений строки лога шаблону
    mismatch_count = 0
    # Словарь для хранения url и списка времени обработки запросов.
    # Вида {"url1": [time1, time2, ..., timeN], "urlN": [...]}
    urls_vs_processing_time = defaultdict(list)

    # Основной цикл обработки лога
    for line in log_iterator:
        # Ищем совпадение по шаблону
        match = nginx_pattern.search(line)
        # Даже если совпадения не найдено, то верим в то что каждая строчка лога - это один запрос
        all_requests_count += 1
        if match:
            request_time = float(match.group("time"))
            urls_vs_processing_time[match.group("url")].append(request_time)
            all_requests_time += request_time
        else:
            mismatch_count += 1

    errors_count = 100.0 * mismatch_count / all_requests_count
    if errors_count > max_errors_percent:
        logging.error(u"Слишком много ошибок при обработке лог-файла: {:.4f}%\n Завершаем работу.".format(errors_count))
        raise ValueError("Слишком много ошибок при обработке лог-файла.")

    report = defaultdict(lambda: defaultdict(float))
    for url, request_time_list in urls_vs_processing_time.iteritems():
        request_time_list.sort()
        # request_time_list = sorted(request_time_list)

        # count ‐ сколько раз встречается URL, абсолютное значение
        count = len(request_time_list)
        report[url]["count"] = count
        # time_sum ‐ суммарный $request_time для данного URL'а, абсолютное значение
        time_sum = sum(request_time_list)
        report[url]["time_sum"] = time_sum
        # count_perc ‐ сколько раз встречается URL, в процентнах относительно общего числа запросов
        report[url]["count_perc"] = 100.0 * count / all_requests_count
        # time_perc ‐ суммарный $request_time для данного URL'а, в процентах относительно общего $request_time всех
        # запросов
        report[url]["time_perc"] = time_sum / all_requests_time * 100
        # time_avg ‐ средний $request_time для данного URL'а
        report[url]["time_avg"] = time_sum / count
        # time_max ‐ максимальный $request_time для данного URL'а
        report[url]["time_max"] = request_time_list[-1]
        # time_med ‐ медиана $request_time для данного URL'а
        report[url]["time_med"] = median(request_time_list)

    top_urls = sorted(report, key=lambda u: report[u]["time_sum"], reverse=True)[:report_size]
    return top_urls, report


def generate_report(report_template, report_name, serialized_dict):
    """
    Функция генерирует отчёт. Путём подстановки в html-шаблон сериализованного словаря-отчёта.
    :param str report_template:
    :param str report_name:
    :param str serialized_dict:
    :return bool:
    """

    try:
        with io.open(report_template, mode='r', encoding="utf-8") as template_file:
            template = Template(template_file.read())
            with tempfile.NamedTemporaryFile(dir=os.path.dirname(report_name)) as temp_file:
                tf_fd = temp_file.fileno()
                temp_file_with_encoding = io.open(tf_fd, mode='w', encoding="utf-8")
                temp_file_with_encoding.write(template.safe_substitute(table_json=serialized_dict))
                os.link(temp_file.name, report_name)

        logging.info(u"Формирование отчёта закончено. Готовый отчёт: {}".format(report_name))

    except IOError, e:
        logging.error(u"Ошибка ввода-вывода при создании отчёта. {}\n Завершаем работу.".format(e))
        return
    return True


def update_config_from_file(fname, current_config):
    """
    Функция изменяет исходный словарь-конфиг current_config согласно данным полученным из файла-конфига fname
    :param str fname:
    :param dict current_config:
    :return bool:
    """

    loglevel = {
        "INFO": 20,
        "DEBUG": 10,
        "ERROR": 40,
    }
    try:
        with open(fname, 'r') as config_file:
            new_config = json.load(config_file)
            current_config.update(new_config)
            current_config["LOGLEVEL"] = loglevel[current_config["LOGLEVEL"]]

    except ValueError, e:
        logging.error(u"Ошибка парсинга конфиг файла! {} \n Завершаем работу.".format(e))
        return
    except IOError, e:
        logging.error(u"Ошибка ввода-вывода при доступе к файлу конфига. {}\n Завершаем работу.".format(e))
        return
    return True


def get_config_name():
    """
    Функция парсит аргументы командной строки и возвращает имя конфиг файла (если задан)
    :return str filename:
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default=None, const=default_cfg_file, nargs='?', help=u'Путь к конфиг файлу.')
    args = parser.parse_args()
    return args.config


def init_logging(cfg):
    """
    Функция инициализирует логирование на основе полученного конфига.
    :param dict cfg:
    :return:
    """

    if cfg["LOGFILE"]:
        logging_dir = os.path.dirname(os.path.abspath(cfg["LOGFILE"]))
        if not os.path.exists(logging_dir):
            raise OSError("Путь к файлу логирования задан не верно: {}! Выходим.".format(logging_dir))

    logging.basicConfig(filename=cfg["LOGFILE"], level=cfg["LOGLEVEL"],
                        format=cfg["LOG_FORMAT"], datefmt=cfg["LOG_DATEFMT"])


def prepare_run(cfg):
    """
    Функция проверяет перед запуском существуют ли необходимые папки, каталоги, по возможности создаёт их.
    :param dict cfg:
    :return:
    """

    # Проверяем папку с логами на существование
    if not os.path.isdir(cfg["LOG_DIR"]):
        raise OSError(u"Каталога с логами {} не существует! Выходим.".format(cfg["LOG_DIR"]))

    # Проверяем папку с отчётами на существование
    if not os.path.isdir(cfg["REPORT_DIR"]):
        # Если не существует, то создадим
        try:
            logging.info(u"Каталога с отчётами {} не существует! Создадим его".format(cfg["REPORT_DIR"]))
            os.mkdir(cfg["REPORT_DIR"])
            logging.info(u"Каталога с отчётами {} Успешно создан".format(cfg["REPORT_DIR"]))
        except OSError as error:
            logging.error(u"Ошибка создания каталога {}: {}\n"
                          u"Завершаем работу.".format(cfg["REPORT_DIR"], error))
            return
    return True


def main(cfg):
    # Инициализируем логирование по первоначальному конфигу
    init_logging(cfg)

    # Если произошла ошибка при подготовке к запуску то выходим
    if not prepare_run(cfg):
        return

    logging.info(u"Ищем последний файл лога...")
    last_log = get_recent_log(cfg["LOG_DIR"], regexprs["LOG_NAME_REGEXP"])
    # Для обработки лог файла убедимся в его наличии
    if last_log:
        logging.info(u"Файл найден: {}".format(last_log.name))
        report_name = os.path.join(cfg["REPORT_DIR"], "report-{}.html".format(last_log.date.strftime("%Y.%m.%d")))
        logging.info(u"Проверяем существует ли отчёт по этому файлу:")

        if os.path.isfile(report_name):
            logging.info(u"Найден отчёт {} Прекращаем работу.".format(report_name))
            return

        logging.info(u"Отчёт не найден. Приступаем к обработке лог файла.")
        log_iterator = read_log(os.path.join(cfg["LOG_DIR"], last_log.name), last_log.extension)
        result = calculate_statistic(log_iterator, regexprs["NGINX_REGEXP"],
                                     cfg["REPORT_SIZE"], cfg["MAX_ERRORS_PERCENT"])
        # Если удалось подсчитать статистику то сформируем отчёт
        if result:
            top_urls, report = result
            serialized_dict = serialize_report_dict(top_urls, report)
            logging.info(u"Обработка закончена. Формируем отчёт.")
            generate_report(cfg["REPORT_TEMPLATE"], report_name, serialized_dict)

    else:
        logging.info(u"Файл не найден! Завершаем работу.")


def match_log_name(files, regexp):
    """
    Функция-генератор, проходится по списку файлов, и возвращает имя лога, дату создания, расширение файла
    :param files:
    :param regexp:
    :return:
    """

    pattern = re.compile(regexp)

    for file_name in files:
        match = pattern.search(file_name)
        if match:
            try:
                cur_date = datetime.strptime(match.group(1), '%Y%m%d')
                yield match.group(0), cur_date, match.group(2)
            except ValueError as error:
                logging.error(u"Ошибка парсинга даты.{}\n Завершаем работу.".format(error))
                raise error


if __name__ == "__main__":
    try:
        # Далее конфиг будем перезаписывать, поэтому сделаем копию.
        cfg = config.copy()
        config_file_name = get_config_name()
        # Если было задано имя конфиг файла, то обновляем локальный конфиг и обновляем логирование
        if config_file_name:
            update_config_from_file(config_file_name, cfg)

        main(cfg)
    except Exception as e:
        logging.exception(e.message)
    logging.shutdown()
