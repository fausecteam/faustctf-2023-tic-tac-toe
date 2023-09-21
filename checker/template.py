#!/usr/bin/env python3

import pwn
import random
import string
import logging

from ctf_gameserver import checkerlib
import utils

pwn.context.timeout = 5

class TemplateChecker(checkerlib.BaseChecker):

    def _connect_to_server(self):
        #TODO:
        try:
            #t = pwn.process("./wrapper")
            t = pwn.remote(self.ip, 3333)
            logging.info(f'_connect_to_server: success')
            #t.settimeout(5)
            return t
        except pwn.pwnlib.exception.PwnlibException:
            logging.error(f'_connect_to_server: connection fails')
            return None

    def _register_user(self, key):
        t = self._connect_to_server()
        if t == None:
            logging.error(f'_register_user: server is unreachable')
            return False, None

        loggedin = False

        while not loggedin:
            t.sendlineafter(b'$ ', b'reg')

            name = ''.join(random.choice(string.ascii_uppercase) for x in range(18))
            t.sendlineafter(b'username:\n', name.encode())

            tmp = t.recvline().strip()
            if tmp == b'user exists':
                logging.error(f'_register_user: user exists already - \"{tmp}\"')
            elif tmp == b'enter the key:':
                t.sendline(key.encode())
                loggedin = True
            else:
                logging.error(f'_register_user: unexpected response - \"{tmp}\"')
                return True, None

        t.sendlineafter(b'$ ', b'exit')
        t.close()

        logging.info(f"_register_user: '{name}' registered with '{key}' as key")

        return True, {'name': name, 'key': key}


    def _login_user(self, user, init=None):
        if init == None:
            logging.info(f'_login_user: create connection')
            t = self._connect_to_server()
        else:
            logging.info(f'_login_user: already connected')
            t = init
        if t == None:
            logging.error(f'_login_user: server is unreachable')
            return False, 'no connection'
        t.sendlineafter(b'$ ', b'login')
        username = user['name']
        key = user['key']
        t.sendlineafter(b'user:\n', username.encode())
        t.sendlineafter(b'password:\n', key.encode())
        #logged in?
        tmp = t.recvline().strip()
        if tmp[-16:] != b': your logged in':
            logging.error(f'_login_user: unable to login - tmp: \"{tmp}\"')
            return False, 'not valid'

        if init == None:
            logging.info(f'_login_user: close connection')
            t.close()

        logging.info(f"_login_user: successfully loggedin '{username}' with '{key}' as key - last line: '{tmp}'")
        return True, 'valid'


    def place_flag(self, tick):
        try:
            flag = checkerlib.get_flag(tick)
            tmp = random.randrange(5, len(flag)//2)
            up, user = self._register_user(flag[tmp:] + flag[:tmp])
            if not up:
                logging.error(f'place_flag: creating user failed')
                return checkerlib.CheckResult.DOWN

            if user == None:
                logging.error(f'place_flag: creating user failed')
                return checkerlib.CheckResult.FAULTY
            else:
                logging.info(f'place_flag: created user')

            checkerlib.store_state('flag_' + str(tick), user)
            checkerlib.set_flagid(user['name'])

            logging.info(f'place_flag: "{user["name"]}" at "{tick}" with "{user["key"]}"')
            return checkerlib.CheckResult.OK
        except ValueError:
            logging.error(f"place_flag: exception")
            return Checkerlib.CheckResult.FAULTY

    def check_service(self):
        #Implement (maybe use `utils.generate_message()`)
        t = self._connect_to_server()
        if t == None:
            logging.error(f'check_service: server is unreachable')
            return checkerlib.CheckResult.DOWN
        else:
            logging.info(f'check_service: connected')
        # check help
        t.sendlineafter(b'$ ', b'help')
        help_list = [b'help      print this message', b'login     log in', b'reg       register new user', b'score     prints score of all users', b'play      play a game of TicTacToe', b'loggedin  as who am i logged in']
        for i in help_list:
            tmp = t.recvline().strip()
            if tmp != i:
                logging.error(f'check_service: (help) {tmp} and {i} are not the same')
                return checkerlib.CheckResult.FAULTY
        logging.info(f"check_service: checked help")
        # check play
        t.sendlineafter(b'$ ', b'play')
        tmp = t.recvline().strip()
        if tmp != b'log in first':
            logging.error(f'check_service: play without login - tmp: \"{tmp}\"')
            return checkerlib.CheckResult.FAULTY
        else:
            logging.info(f'check_service: (play) login check')

        key = ''.join(random.choice(string.ascii_uppercase) for x in range(20))
        up, user = self._register_user(key)
        if not up:
            logging.error(f'check_service: creating user failed')
            return checkerlib.CheckResult.DOWN

        if user == None:
            logging.error(f'check_service: creating user failed')
            return checkerlib.CheckResult.FAULTY
        else:
            logging.info(f'check_service: (play) created user')

        verdict, msg = self._login_user(user, t)
        if verdict == False:
            logging.error(f'check_service: unable to login - msg: \"{msg}\"')
            return checkerlib.CheckResult.FAULTY
        else:
            logging.info(f'check_service: logged in')

        t.sendlineafter(b'$ ', b'play')
        t.recvline()
        tmp = t.recvline().strip()
        if tmp != b'3':
            logging.error(f'check_service: unexpected response after play - \"{tmp}\"')
            return checkerlib.CheckResult.FAULTY
        else:
            logging.info(f'check_service: (play) start playing')

        end = b'not'
        i = 0
        while end != b'no one won' and end != b'you lost' and end != b'congrats you won!':
            logging.info(f"""check_service: (play) round {i}""")
            if i > 9:
                logging.error(f"""check_service: (play) round still going after 9 moves - '{end}'""")
                return checkerlib.CheckResult.FAULTY
            input = list('11')
            resp = b'invalid input'
            while resp == b'invalid input':
                t.sendlineafter(b'input two numbers ranging from 1 to 3 [eg. 12]\n', ("".join(input)).encode())
                resp = t.recvline().strip()
                logging.info(f'check_service: (play) send: "{input[0]} {input[1]}" got resp: {resp}')
                #prevent infloop
                if int(input[0]) <= 3:
                    if int(input[1]) < 3:
                        input[1] = str(int(input[1]) + 1)
                    else:
                        input[1] = '1'
                        input[0] = str(int(input[0]) + 1)
                else:
                    logging.error(f'check_service: (play) no valid move left')
                    return checkerlib.CheckResult.FAULTY

            for k in range(5):
                t.recvline()
            end = t.recvline().strip()
            logging.info(f'check_service: (play) place one item - \"{end}\"')
            i += 1

        logging.info(f"check_service: checked play")

        return checkerlib.CheckResult.OK

    def check_flag(self, tick):
        try:
            user = checkerlib.load_state('flag_' + str(tick))
            if not user:
                logging.error(f'check_flag: user at "{tick}" not found from state')
                return checkerlib.CheckResult.FLAG_NOT_FOUND
            logging.info(f"""check_flag: found user at "{tick}" - name:"{user['name']}" key:"{user['key']}\"""")

            verdict, msg = self._login_user(user)
            if verdict == False and msg == 'no connecton':
                logging.error(f'check_flag: server is unreachable')
                return checkerlib.CheckResult.DOWN
            elif verdict == False:
                logging.info(f'check_flag: user "{user["name"]}" "{msg}"')
                return checkerlib.CheckResult.FLAG_NOT_FOUND
            else:
                logging.info(f'check_flag: user "{user["name"]}" checked')
                return checkerlib.CheckResult.OK
        except ValueError:
            logging.error(f"check_flag: exception")
            return checkerlib.CheckResult.FAULTY

if __name__ == '__main__':

    checkerlib.run_check(TemplateChecker)
