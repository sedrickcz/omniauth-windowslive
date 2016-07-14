require 'omniauth/strategies/oauth2'

# http://msdn.microsoft.com/en-us/library/hh243647.aspx
# http://msdn.microsoft.com/en-us/library/hh243649.aspx

module OmniAuth
  module Strategies
    class Windowslive < OmniAuth::Strategies::OAuth2
      # Scopes and permissions => http://msdn.microsoft.com/en-us/library/hh243646.aspx
      DEFAULT_SCOPE = 'bingads.manage'

      option :client_options, {
        site:          'https://login.live.com',
        authorize_url: '/oauth20_authorize.srf',
        token_url:     '/oauth20_token.srf'
      }

      option :authorize_params, {
        response_type: 'code'
      }

      option :token_params, {
        grant_type: 'authorization_code'
      }

      option :name, 'windowslive'

      option :uid_field, :user_id

      uid do
        request.params[options.uid_field.to_s]
      end

      # http://msdn.microsoft.com/en-us/library/hh243648.aspx
      info do
        {
          'intentionally left blank' => true
          #'id'           => raw_info['id'],
          #'emails'       => emails_parser,
          #'name'         => raw_info['name'],
          #'first_name'   => raw_info['first_name'],
          #'last_name'    => raw_info['last_name'],
          #'gender'       => raw_info['gender'],
          #'link'         => raw_info['link'],
          #'locale'       => raw_info['locale'],
          #'updated_time' => raw_info['updated_time']
        }
      end

      extra do
        {
          'intentionally left blank' => true
          #'raw_info' => raw_info
        }
      end

      # http://msdn.microsoft.com/en-us/library/hh243649.aspx
      def raw_info
        request = 'https://apis.live.net/v5.0/me'
        @raw_info ||= MultiJson.decode(access_token.get(request).body)
      end

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      private

      def emails_parser
        emails = raw_info['emails']
        emails_parsed = []

        if emails
          if emails['preferred']
            emails_parsed << { 'value' =>  emails['preferred'], 'type' => 'preferred', 'primary' => true }
          end

          if emails['account']
            emails_parsed << { 'value' =>  emails['account'], 'type' => 'account' }
          end

          if emails['personal']
            emails_parsed << { 'value' =>  emails['personal'], 'type' => 'personal' }
          end

          if emails['business']
            emails_parsed << { 'value' =>  emails['business'], 'type' => 'business' }
          end

          if emails['other']
            emails_parsed << { 'value' =>  emails['other'], 'type' => 'other' }
          end
        end

        emails_parsed
      end
    end
  end
end

OmniAuth.config.add_camelization 'windowslive', 'Windowslive'
