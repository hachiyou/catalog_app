#!/usr/bin/python3
from flask import Flask, render_template, request, redirect,jsonify, url_for, flash
app = Flask(__name__)

from sqlalchemy import create_engine, desc
from sqlalchemy.orm import sessionmaker
from models import Base, Category, Item, User

from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

# Google Signin Tutorial: https://developers.google.com/identity/sign-in/web/sign-in#before_you_begin

CLIENT_ID = json.loads(
    open('credentials.json', 'r').read())['web']['client_id']

#Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)


#JSON APIs to view Catalog Information
@app.route('/catalog.json')
def catalogJSON():
    session = DBSession()

    categories = session.query(Category).all()
    listCate = [l.serialize for l in categories]

    for c in listCate:
        items = session.query(Item).filter_by(category_id=c['id']).all()
        if len(items) > 0:
            c['items'] = [i.serialize for i in items]

    return jsonify(listCate)


@app.route('/')
def showHomePage():
    session = DBSession()
    categories = session.query(Category).all()
    recent_items = session.query(Item).order_by(desc(Item.id)).limit(10).all()
    return render_template('index.html', categories=categories, items=recent_items)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 8000)
