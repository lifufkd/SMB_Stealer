from datetime import datetime


class Logger:
    def __init__(self, data_folder, startup):
        super(Logger, self).__init__()
        self.folder = data_folder
        self.startup = startup

    def logger(self, msg):
        if self.startup:
            with open(f'{self.folder}/log.txt', 'a', encoding='utf-8') as fp:
                fp.write(f'\n\n\nStart time - {datetime.now()}\n{"%" * 50}')
            self.startup = False
        if len(msg) > 1:
            data = msg[1]
        else:
            data = msg[0]
        with open(f'{self.folder}/log.txt', 'a', encoding='utf-8') as fp:
            fp.write(f'\n{data}')
        if len(msg[0]) != 0:
            print(msg[0])