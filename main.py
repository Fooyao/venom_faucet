import asyncio
import base64
import sys
import httpx
from loguru import logger
from tonclient.test.helpers import async_core_client
from tonclient.types import AbiParam, ParamsOfSign, ParamsOfHash, ParamsOfGetBocHash, MnemonicDictionary, ParamsOfAbiEncodeBoc, ParamsOfEncodeStateInit, ParamsOfMnemonicFromRandom, ParamsOfMnemonicDeriveSignKeys

logger.remove()
logger.add(sys.stdout, colorize=True, format="<g>{time:HH:mm:ss:SSS}</g> | <c>{level}</c> | <level>{message}</level>")


async def nocaptcha(User_Token):
    try:
        headers = {
            'User-Token': User_Token,
            'Developer-Id': 'dwBf1P'
        }
        json_data = {
            'sitekey': '106e57f5-f9fd-4ac7-b086-ad720846f181',
            'referer': 'https://venom.network',
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
        }
        async with httpx.AsyncClient(verify=False, timeout=60) as client:
            resp = await client.post('http://api.nocaptcha.io/api/wanda/hcaptcha/universal', headers=headers, json=json_data)
            if resp.status_code == 200 and resp.json()['status'] == 1:
                return resp.json()['data']['generated_pass_UUID']
            else:
                return None
    except:
        return None


class tonclient:
    def __init__(self, mnemonic=None, keypair=None):
        if mnemonic is None:
            self.random_mnemonic()
        else:
            self.mnemonic = mnemonic
        if keypair is None:
            self.get_keypair_from_mnemonic(self.mnemonic)
        else:
            self.keypair = keypair
        self.get_address_from_keypair()

    def random_mnemonic(self):
        params = ParamsOfMnemonicFromRandom()
        mnemonic = async_core_client.crypto.mnemonic_from_random(params).phrase
        self.mnemonic = mnemonic

    def get_keypair_from_mnemonic(self, mnemonic):
        derive_params = ParamsOfMnemonicDeriveSignKeys(phrase=mnemonic, dictionary=MnemonicDictionary.ENGLISH, word_count=12)
        keypair = async_core_client.crypto.mnemonic_derive_sign_keys(derive_params)
        self.keypair = keypair

    def get_address_from_keypair(self):
        walletCode = 'te6cckEBBgEA/AABFP8A9KQT9LzyyAsBAgEgAgMABNIwAubycdcBAcAA8nqDCNcY7UTQgwfXAdcLP8j4KM8WI88WyfkAA3HXAQHDAJqDB9cBURO68uBk3oBA1wGAINcBgCDXAVQWdfkQ8qj4I7vyeWa++COBBwiggQPoqFIgvLHydAIgghBM7mRsuuMPAcjL/8s/ye1UBAUAmDAC10zQ+kCDBtcBcdcBeNcB10z4AHCAEASqAhSxyMsFUAXPFlAD+gLLaSLQIc8xIddJoIQJuZgzcAHLAFjPFpcwcQHLABLM4skB+wAAPoIQFp4+EbqOEfgAApMg10qXeNcB1AL7AOjRkzLyPOI+zYS/'
        params = [{"name": "publicKey", "type": "uint256"}, {"name": "timestamp", "type": "uint64"}]
        params = [AbiParam(info['name'], info['type']) for info in params]
        params = ParamsOfAbiEncodeBoc(params, data={"publicKey": f'0x{self.keypair.public}', "timestamp": 0})
        initData = async_core_client.abi.encode_boc(params).boc
        params = ParamsOfEncodeStateInit(code=walletCode, data=initData)
        stateInit = async_core_client.boc.encode_state_init(params).state_init
        params = ParamsOfGetBocHash(stateInit)
        walletBochash = async_core_client.boc.get_boc_hash(params).hash
        self.address = f'0:{walletBochash}'

    def sign_msg(self):
        unsigned = 'V2UgYXBwcmVjaWF0ZSB5b3VyIHBhcnRpY2lwYXRpb24gaW4gdGhlIFZlbm9tIFRlc3RuZXQuIFlvdSB3aWxsIHJlY2VpdmUgZmF1Y2V0IHRva2VucyBmb3IgdGFraW5nIHBhcnQgaW4gdGhlIFRlc3RuZXQgYW5kIGFjdGlvbmFibGUgaXRlbXMuIFRoZSBUZXN0bmV0IHRva2VucyBjYW4gYmUgdXNlZCBmb3IgdGVzdG5ldC1yZWxhdGVkIGFjdGl2aXRpZXMgb25seS4gUGxlYXNlIG5vdGUgdGhhdCB0aGUgVmVub20gVGVzdG5ldCBUb2tlbnMgaGF2ZSBubyBtb25ldGFyeSB2YWx1ZS4='
        params = ParamsOfHash(data=unsigned)
        msgHash = async_core_client.crypto.sha256(params=params).hash
        unsigned = base64.b64encode(bytes.fromhex(f'000003e8{msgHash}')).decode()
        sign_params = ParamsOfSign(unsigned=unsigned, keys=self.keypair)
        signature = async_core_client.crypto.sign(params=sign_params).signature
        signature = base64.b64encode(bytes.fromhex(signature)).decode()
        payload = f'{msgHash}.{self.keypair.public}.{signature}'
        return payload


class faucet:
    def __init__(self, nocaptcha_key, twitter_token, proxy, mnemonic=None):
        if 'http' in proxy:
            self.proxies = {'all://': proxy}
        else:
            self.proxies = {'all://': f'http://{proxy}'}
        self.http = httpx.AsyncClient(verify=False, timeout=120, proxies=self.proxies)
        self.auth_token = twitter_token
        self.nocaptcha_key = nocaptcha_key
        self.TC = tonclient(mnemonic)
        self.http.headers.update({
            'wallet-address': self.TC.address,
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36'
        })
        self.http.cookies.update({'auth_token': self.auth_token})
        logger.info(f'助记词:{self.TC.mnemonic}')
        logger.info(f'地址:{self.TC.address}')

    async def get_oauth_token(self):
        try:
            captcha = await nocaptcha(self.nocaptcha_key)
            if captcha is None:
                logger.error(f"[{self.TC.address[:10]}*******] 获取captcha失败.")
            params = {
                'successRedirectUri': 'https://venom.network/tasks',
                'errorRedirectUri': 'https://venom.network/tasks'
            }
            headers = {'h-captcha': captcha}
            res = await self.http.get('https://venom.network/api/auth/twitter/oauth/sign_in', params=params, headers=headers)
            if res.status_code == 200:
                oauth_token = res.text.split('oauth_token=')[1]
                return oauth_token
            else:
                logger.error(f"[{self.TC.address[:10]}*******] 获取oauth_token失败.")
                return None
        except Exception as e:
            logger.error(f"[{self.TC.address[:10]}*******] 获取oauth_token失败{e}")
            return None

    async def oauth_verifier(self):
        try:
            oauth_token = await self.get_oauth_token()
            if oauth_token is None:
                return None
            res = await self.http.get(f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}')
            if res.status_code == 200 and 'authenticity_token' in res.text:
                authenticity_token = res.text.split('name="authenticity_token" type="hidden" value="')[1].split('"')[0]
                data = {
                    'authenticity_token': authenticity_token,
                    'redirect_after_login': f'https://api.twitter.com/oauth/authorize?oauth_token={oauth_token}',
                    'oauth_token': oauth_token
                }
                res = await self.http.post('https://api.twitter.com/oauth/authorize', data=data)
                if res.status_code == 200 and 'oauth_verifier' in res.text:
                    oauth_verifier = res.text.split('oauth_verifier=')[1].split('"')[0]
                    return oauth_token, oauth_verifier
                else:
                    if 'This account is suspended.' in res.text:
                        logger.error(f'[{self.TC.address[:10]}*******] 获推特账号被封禁.')
                        return None, None
                    logger.error(f'[{self.TC.address[:10]}*******] 获取oauth_verifier失败：{res.status_code}')
                    return None, None
            else:
                logger.error(f'[{self.TC.address[:10]}*******] 获取authenticity_token失败：{res.status_code}')
                return None, None
        except Exception as e:
            logger.error(f'[{self.TC.address[:10]}*******] 获取authenticity_token失败：{e}')
            return None, None

    async def bind_twitter(self):
        try:
            oauth_token, oauth_verifier = await self.oauth_verifier()
            if oauth_token is None or oauth_verifier is None:
                return False
            params = {
                'oauth_token': oauth_token,
                'oauth_verifier': oauth_verifier
            }
            res = await self.http.get('https://venom.network/api/auth/twitter/oauth/callback', params=params, follow_redirects=False)
            if res.status_code == 302 and res.headers['location'] == 'https://venom.network/tasks':
                logger.info(f'[{self.TC.address[:10]}*******] 绑定twitter成功')
                return True
            elif res.status_code == 302 and 'message=' in res.headers['location']:
                logger.error(f'[{self.TC.address[:10]}*******] 绑定twitter失败：{res.headers["location"].split("message=")[1].replace("+", " ")}')
                return False
            else:
                logger.error(f'[{self.TC.address[:10]}*******] 绑定twitter失败：{res.text}')
                return False
        except Exception as e:
            logger.error(f'[{self.TC.address[:10]}*******] 绑定twitter失败：{e}')
            return False

    async def solving_twitter(self, task_ids):
        try:
            done_list = []
            info = ''
            for task_id in task_ids:
                json_data = {"taskId": task_id}
                res = await self.http.post('https://venom.network/api/tasks/solving/twitter', json=json_data)
                if res.status_code == 201 and res.json()['status'] == 'done':
                    info += f'{task_id}完成,'
                    done_list.append(task_id)
                else:
                    info += f'[{self.TC.address[:10]}*******] 任务{task_id}失败,'
            logger.info(f'[{self.TC.address[:10]}*******] 任务：{info[:-1]}')
            return done_list
        except Exception as e:
            logger.error(f'任务失败：{e}')
            return False

    async def claim(self, task_ids):
        try:
            done_lsit = await self.solving_twitter(task_ids)
            if len(done_lsit) == 0:
                return False
            json_data = {"taskIds": task_ids}
            headers = {
                'asymmetric-keys-with-hash-payload': self.TC.sign_msg()
            }
            res = await self.http.post('https://venom.network/api/tasks/claim', json=json_data, headers=headers, timeout=300)
            if res.status_code == 201:
                token, info, alltoken = {18: 50, 36: 15, 42: 15}, '', 0
                for _task in res.json():
                    task_id = _task["taskId"]
                    if _task["status"] == 'claimed':
                        info += f'{task_id}:{token[task_id]}|'
                        alltoken += token[task_id]
                    else:
                        info += f'{task_id}:{0}|'
                logger.info(f'[{self.TC.address[:10]}*******] 领水：{info[:-1]},总共领水:{alltoken}个')
                with open('领水成功.txt', 'a') as f:
                    f.write(f'{self.TC.address}----{self.TC.mnemonic}')
                return True
            else:
                logger.error(f'[{self.TC.address[:10]}*******] 领水失败：{res.status_code}')
                return False
        except Exception as e:
            logger.error(f'[{self.TC.address[:10]}*******] 领水失败：{e}')
            return False


async def task(semaphore, nocaptcha_key, proxy, twitter_token, mnemonic=None):
    async with semaphore:
        Faucet = faucet(nocaptcha_key, twitter_token, proxy, mnemonic)
        if await Faucet.bind_twitter():
            await Faucet.claim([18, 36, 42])


async def main(nocaptcha_key, account_file, proxy, thread_num):
    semaphore = asyncio.Semaphore(thread_num)
    task_list = []
    with open(account_file, 'r') as f:
        for line in f:
            line = line.strip()
            if '----' in line:
                mnemonic = line.split('----')[1]
                twitter = line.split('----')[2]
                task_list.append(task(semaphore, nocaptcha_key, proxy, twitter, mnemonic))
            else:
                task_list.append(task(semaphore, nocaptcha_key, proxy, line))

    await asyncio.gather(*task_list)


if __name__ == '__main__':
    _nocaptcha_key = input('输入nocaptcha_key：')
    print('账号文本格式为：地址----助记词----推特token 或 推特token，每行一个。')
    _acc_file = input('输入账号文件完整路径(直接拖入)：')
    _thread = input('输入并发数：')
    _proxy = input('输入代理(随机代理)：')
    asyncio.run(main(_nocaptcha_key.strip(), _acc_file.strip(), _proxy.strip(), int(_thread.strip())))
