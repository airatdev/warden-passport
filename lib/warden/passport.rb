require "warden/passport/version"
require "warden/passport/strategy"

Warden::Strategies.add(:passport, Warden::Passport::Strategy)
