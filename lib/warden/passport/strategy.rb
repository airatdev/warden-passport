module Warden
  module Passport
    class Strategy < Warden::Strategies::Base
      def valid?
        params[:user] && params[:user][:email] && params[:user][:password]
      end

      def authenticate!
        user = User.where(email: params[:user][:email]).first

        encrypted_password = OpenSSL::PKCS5.pbkdf2_hmac_sha1(
          params[:user]['password'],
          user.read_attribute(:salt),
          ENV['PBKDF2_ITERATIONS'].to_i,
          ENV['PBKDF2_LENGTH'].to_i
        ).unpack('H*')[0]

        if encrypted_password == user.read_attribute(:hash)
          success!(user)
        else
          fail!('Could not log in')
        end
      end
    end
  end
end
