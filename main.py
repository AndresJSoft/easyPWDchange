import paramiko
import time
from pathlib import Path
import json
import logging

class PasswordChanger:
    def __init__(self):
        self.private_key = None
        self.admin_name = None
        self.admin_password = None

    def set_administrator(self, admin_name, admin_password, key_type, private_key_file, passphrase = None):
        try:
            if key_type == 'rsa':
                self.private_key = paramiko.RSAKey.from_private_key_file(private_key_file, password=passphrase)
            elif key_type == 'ecdsa':
                self.private_key = paramiko.ECDSAKey.from_private_key_file(private_key_file, password=passphrase)
            elif key_type == 'ed25519':
                self.private_key = paramiko.Ed25519Key.from_private_key_file(private_key_file, password=passphrase)
        except Exception as e:
            print(f"Ошибка загрузки ключа: {e}")
            self.private_key = None
        self.admin_name = admin_name
        self.admin_password = admin_password


    def change_linux_password(self, host_name, port,
                              user_name, new_password):
        if (self.private_key is None):
            return False, 'Ошибка: не загружен приватный ключ.'
        ssh_client = paramiko.SSHClient()
        ### TODO Change policy
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh_client.connect(
                hostname=host_name,
                port = port,
                username=self.admin_name,
                pkey=self.private_key)

            ssh_shell = ssh_client.invoke_shell()
            commands = [f"echo \"{self.admin_password}\" | sudo -S su -",
                        "sudo su -",
                        f"echo -e '{new_password}\n{new_password}' | passwd {user_name}"
                        ]
            for command in commands:
                ssh_shell.send(command + "\n")
                time.sleep(0.1)
            output = ssh_shell.recv(1024)
            ssh_client.close()
            return True, output.decode()
        except paramiko.AuthenticationException:
            ssh_client.close()
            return False, 'Ошибка аутентификации. Проверьте учетные данные.'
        except paramiko.SSHException as e:
            ssh_client.close()
            return False, f'Ошибка SSH: {str(e)}'
        except socket.timeout:
            ssh_client.close()
            return False, 'Тайм-аут при подключении к серверу'
        except Exception as e:
            ssh_client.close()
            return False, f'Непредвиденная ошибка: {str(e)}'

if __name__ == '__main__':

    password_changer = PasswordChanger()

    logging.basicConfig(
        filename=str(Path.cwd().joinpath('change_passwords.log')),
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        encoding='utf-8'
    )

    logging.info('Начало работы программв установки паролей')
    logging.info('Загружаем данные из файла ' + str(Path.cwd().joinpath('servers.json')))
    data = json.loads(str(Path.cwd().joinpath('servers.json').read_text()))
    if 'global_data' in data:
        global_data = data['global_data']
    else:
        global_data = None
    servers = data['servers']
    for server in servers:
        if 'admin_name' in server:
            admin_name = server['admin_name']
            admin_password = server['admin_password']
            key_type = server['key_type']
            key_file = server['key_file']
        else:
            if global_data is None:
                logging.error('Ошибка в файле данных: отсутствуют данные администратор для подключения к серверу')
                break
            admin_name = global_data['admin_name']
            admin_password = global_data['admin_password']
            key_type = global_data['key_type']
            key_file = global_data['key_file']
        host = server['host']
        port = server['port']
        for user in server['users']:
            user_name = user['user_name']
            if 'password' in user:
                password = user['password']
            else:
                if 'password' in global_data:
                    password = global_data['password']
                else:
                    logging.error('Ошибка в файле данных: отсутствуют новый пароль пользователя для установки')
                    break
            password_changer.set_administrator(admin_name, admin_password, key_type, key_file)
            logging.info('Устанавливаем пароль пользователю ' + user_name + ' на сервере ' + host)
            result, message = password_changer.change_linux_password(host, port, user_name, password)
            if result:
                #logging.info(message)
                logging.info('Процедура завершилась успешно, вероятнее всего пароль установлен')
            else:
                logging.error(message)
    logging.info('Окончание работы программв установки паролей')


