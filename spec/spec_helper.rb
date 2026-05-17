ENV['RACK_ENV'] = 'test'

require 'rack/test'
require 'rspec'
require_relative '../server'

module RSpecMixin
  include Rack::Test::Methods
  def app() Sinatra::Application end
end

RSpec.configure do |config|
  config.include RSpecMixin
  
  config.before(:each) do
    Rack::Attack.reset!
    header 'Host', 'localhost'
  end
end