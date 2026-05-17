require 'bundler/setup'
require './server'

# Лимит размера запроса
use Rack::ContentLength
use Rack::TempfileReaper

run Sinatra::Application
