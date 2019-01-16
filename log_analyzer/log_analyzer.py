#!/usr/bin/env python2.7
# -*- coding: utf-8 -*-

import os
import re
from datetime import datetime
import gzip
import io
from collections import defaultdict
import logging
import argparse

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
    "LOG_NAME_REGEXP": r'^nginx-access-ui\.log-(\d{8})(\.\w*){0,1}',
    "NGINX_REGEXP": r'\"[A-Z]+\s(?P<url>[\S]+)\s.+\"\s(?P<time>\S+)$',
}


def get_recent_log(log_dir, regexp):
    """
    Ищет в директории log_dir логи согласно регулярному выражению regexp
    И возвращает самый новый, согласно дате создания
    :param str log_dir:
    :param str regexp:
    :return:
    """
    pattern = re.compile(regexp)
    recent_log = None
    recent_date = None

    files = os.listdir(log_dir)

    # Если каталог пуст то сразу выходим
    if len(files) == 0:
        return None

    for file_name in files:
        match = pattern.search(file_name)
        if match:
            try:
                cur_date = datetime.strptime(match.group(1), '%Y%m%d')
            except ValueError as error:
                logging.error(u"Ошибка парсинга даты.{}\n Завершаем работу.".format(error))
                return
            try:
                if recent_date < cur_date:
                    recent_date = cur_date
                    recent_log = match
            # Так проще, чем задавать "нулевую" дату
            except TypeError as error:
                if not recent_date:
                    recent_date = cur_date
                    recent_log = match
                else:
                    raise error

    # Возвращаем имя лога, дату создания, расширение файла
    if recent_log:
        return recent_log.group(0), recent_date, recent_log.group(2)
    else:
        return None


def read_log(log_full_name, file_type):
    """
    Функция - генератор. Итерируется по лог-файлу построчно
    :param str log_full_name:
    :param str file_type:
    """
    f_open = gzip.open if file_type == '.gz' else io.open
    try:
        for line in f_open(log_full_name, mode='r'):
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
    json_pattern = '{{"count": {count}, "time_avg": {time_avg:.4f}, "time_max": {time_max},' \
                   ' "time_sum": {time_sum}, "url": "{url}", "time_med": {time_med}, "time_perc": {time_perc:.4f},' \
                   ' "count_perc": {count_perc:.2f}}},'
    serialized_report = '['
    for url in top_urls:
        statistic = report_dict[url]
        serialized_report += json_pattern.format(url=url, **statistic)
    serialized_report += ']'
    return serialized_report


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
        try:
            # Ищем совпадение по шаблону
            match = nginx_pattern.search(line)
        except TypeError, e:
            logging.error(u"Обнаружена ошибка при обработки строки из лог-файла: {}\n Завершаем работу.".format(e))
            return None
        # Даже если совпадения не найдено, то верим в то что каждая строчка лога - это один запрос
        all_requests_count += 1
        if match:
            request_time = float(match.group("time"))
            urls_vs_processing_time[match.group("url")].append(request_time)
            all_requests_time += request_time
        else:
            mismatch_count += 1

    errors_count = 100.0 * mismatch_count / all_requests_count
    if errors_count >= max_errors_percent:
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
        with io.open(report_template, mode='r', encoding="utf-8") as template_file, \
                io.open(report_name, mode='w', encoding="utf-8") as report_file:
            template = "\n".join(template_file.readlines())
            report_file.write(re.sub(r'\$table_json', serialized_dict, template))
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
    # Не уверен, но думаю для экономии памяти эту библиотеку лучше импортировать здесь
    # Так как это не часто "употребляемая" функция
    import json
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


def parse_arguments():
    """
    Функция парсит аргументы командной строки и возвращает имя конфиг файла (если задан)
    :return str filename:
    """

    parser = argparse.ArgumentParser()
    parser.add_argument('--config', default=None, nargs='*', help=u'Путь к конфиг файлу.')
    args = parser.parse_args()

    # Это конечно не однозначно, но тут мы проверяем не задали ли пользователь --config без указания имени файла?
    if args.config is not None:
        if len(args.config) == 0:
            cfg_file = default_cfg_file
        else:
            cfg_file = args.config[0]

        return cfg_file


def init_logging(cfg):
    """
    Функция инициализирует логирование на основе полученного конфига.
    :param dict cfg:
    :return:
    """
    logging.basicConfig(filename=cfg["LOGFILE"], level=cfg["LOGLEVEL"],
                        format=cfg["LOG_FORMAT"], datefmt=cfg["LOG_DATEFMT"])


def update_logging(cfg):
    """
    Функция обновляет логирование, на основе полученного конфига.
    :param dict cfg:
    :return:
    """
    log = logging.getLogger()
    for hdlr in log.handlers[:]:
        log.removeHandler(hdlr)

    file_handler = logging.FileHandler(cfg["LOGFILE"], 'a')
    file_handler.setFormatter(logging.Formatter(cfg["LOG_FORMAT"], datefmt=cfg["LOG_DATEFMT"]))

    log.addHandler(file_handler)


def prepare_run(cfg):
    """
    Функция проверяет перед запуском существуют ли необходимые папки, каталоги, по возможности создаёт их.
    :param dict cfg:
    :return:
    """
    # Проверяем папку с логами на существование
    if not os.path.isdir(cfg["LOG_DIR"]):
        logging.error(u"Каталога с логами {} не существует! Выходим.".format(cfg["LOG_DIR"]))
        return

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


def main():
    # Инициализируем логирование по первоначальному конфигу
    init_logging(config)
    # Парсим аргументы командной строки
    config_file_name = parse_arguments(config)
    # Если было задано имя конфиг файла, то обновляем локальный конфиг и обновляем логирование
    if config_file_name:
        update_config_from_file(config_file_name, config)
        update_logging(config)

    # Если произошла ошибка при подготовке к запуску то выходим
    if not prepare_run(config):
        return

    logging.info(u"Ищем последний файл лога...")
    last_log = get_recent_log(config["LOG_DIR"], regexprs["LOG_NAME_REGEXP"])
    # Для обработки лог файла убедимся в его наличии
    if last_log:
        log_name, log_date, log_type = last_log
        logging.info(u"Файл найден: {}".format(log_name))
        report_name = os.path.join(config["REPORT_DIR"], "report-{}.html".format(log_date.strftime("%Y.%m.%d")))
        logging.info(u"Проверяем существует ли отчёт по этому файлу:")

        if os.path.isfile(report_name):
            logging.info(u"Найден отчёт {} Прекращаем работу.".format(report_name))
            return

        logging.info(u"Отчёт не найден. Приступаем к обработке лог файла.")
        log_iterator = read_log(os.path.join(config["LOG_DIR"], log_name), log_type)
        result = calculate_statistic(log_iterator, regexprs["NGINX_REGEXP"],
                                     config["REPORT_SIZE"], config["MAX_ERRORS_PERCENT"])
        # Если удалось подсчитать статистику то сформируем отчёт
        if result:
            top_urls, report = result
            serialized_dict = serialize_report_dict(top_urls, report)
            logging.info(u"Обработка закончена. Формируем отчёт.")
            generate_report(config["REPORT_TEMPLATE"], report_name, serialized_dict)

    else:
        logging.info(u"Файл не найден! Завершаем работу.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception(e)
    logging.shutdown()
