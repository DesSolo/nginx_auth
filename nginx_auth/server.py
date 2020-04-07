import logging
from aiohttp import web
from typing import Mapping
import config
from models import get_model_class
from authirisations import get_authorisation_class
from cookies_manager import CookiesManager

logging.basicConfig(level=logging.INFO)

routes = web.RouteTableDef()

cookie_manager = CookiesManager(config.SECRET_KEY)
authorisation = get_authorisation_class(config.AUTHORISATION)
headers_model = get_model_class(config.AUTHORISATION)


def parse_headers(response_headers: Mapping):
    try:
        return headers_model(**response_headers)
    except ValueError:
        return None


def is_valid_cookies(cookies: Mapping, ip, user_agent) -> bool:
    session_id = cookies.get(config.COOKIE_KEY)
    if not session_id:
        return False
    if cookie_manager.is_valid(session_id, ip, user_agent):
        return True
    return False


def is_valid_credentials(headers: authorisation) -> bool:
    if not headers.authorization:
        return False
    logging.info(f'Try authorise {headers}')
    if authorisation.authorise(
            headers.authorization.username,
            headers.authorization.password.get_secret_value(),
            headers.real_ip,
            headers.realm
    ):
        return True
    logging.info(f'Auth failed {headers}')
    return False


@routes.view('/login')
async def login(request: web.Request):
    headers = parse_headers(request.headers)
    if not headers:
        return web.HTTPForbidden()
    if is_valid_cookies(request.cookies, headers.real_ip, headers.user_agent):
        return web.Response(text='Cookies valid', status=200)
    if is_valid_credentials(headers):
        token = cookie_manager.generate_new(headers.real_ip, headers.user_agent, headers.authorization.username)
        response = web.Response(
            text='Auth success',
            status=200,
            headers={'X-Auth-User': headers.authorization.username}
        )
        response.set_cookie(config.COOKIE_KEY, token)
        logging.info(f'Auth success username: {headers.authorization.username} token: {token}')
        return response
    return web.HTTPUnauthorized(headers={'WWW-Authenticate': f'Basic realm="{headers.realm}"'})


@routes.view('/logout')
async def logout(request: web.Request):
    response = web.Response(text='', status=403)
    response.del_cookie(config.COOKIE_KEY)
    return response


if __name__ == '__main__':
    app = web.Application()
    app.add_routes(routes)
    web.run_app(app, port=config.LISTEN_PORT)
