# -*- coding: utf-8 -*-
import time
import logging
from odoo import models, api, fields


_logger = logging.getLogger(__name__)

try:
    import secrets
    def token_urlsafe():
        return secrets.token_urlsafe(64)
except ImportError:
    import re
    import uuid
    import base64
    def token_urlsafe():
        rv = base64.b64encode(uuid.uuid4().bytes).decode('utf-8')
        return re.sub(r'[\=\+\/]', lambda m: {'+': '-', '/': '_', '=': ''}[m.group(0)], rv)

class WebApis(models.Model):
	_name = 'web_apis.token'
    
	token = fields.Char(string="Acess Token",required=True)
	number = fields.Integer(string="Number",required=True)
	res_user = fields.Many2one('res.users',string="User",required=True)

	
	@api.model
	def Checklifetime_token(self, token):
		token = self.search([['token', '=', token]], limit=1)
		if token:
			return int(token.number - time.time())
		return False

	@api.model
	def check_access_token(self, token):
		token = self.search([['token', '=', token]], limit=1)
		return token.res_user.id if token and int(time.time()) < token.number else False

	@api.model
	def generate_token(self, uid, lifetime=3600):
		token = token_urlsafe()
		timestamp = int(time.time() + lifetime)
		return self.create({'token': token, 'number': timestamp, 'res_user': uid})



