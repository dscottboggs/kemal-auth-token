require "kemal"
require "jwt"
require "json"

# Signed user is stored as a Hash
alias UserHash = Hash(String, (String | Int32 | Nil | Bool))

class Kemal::AuthToken
  include HTTP::Handler

  @sign_in : Proc(String, String, UserHash)?
  @load_user : Proc(Hash(String, JSON::Any), UserHash)?

  def initialize(@secret_key = Random::Secure.hex,
                 @algorithm = "HS256",
                 @path = "/sign_in")
  end

  def sign_in(&block : String, String -> UserHash)
    @sign_in = block
  end

  def load_user(&block : Hash(String, JSON::Any) -> UserHash)
    @load_user = block
  end

  getter :secret_key, :algorithm
  property :path

  def call(context)
    # sign_in
    if (sign_in_proc = @sign_in) && (load_user_proc = @load_user)
      if context.request.path == @path
        if context.params.body["email"]? && context.params.body["password"]?
          uh = sign_in_proc.call(context.params.body["email"], context.params.body["password"])
          if uh["id"]?
            # that means it's ok
            token = JWT.encode(uh, @secret_key, @algorithm)
            context.response << {token: token}.to_json
            return context
          end
        end
      end
      # auth
      if context.request.headers["X-Token"]?
        token = context.request.headers["X-Token"]
        payload, header = JWT.decode(token, @secret_key, @algorithm)
        payload
        context.current_user = load_user_proc.call(payload)
      end
      call_next context
    else
      raise "\
		you MUST call Kemal::AuthToken#sign_in and \
		Kemal::AuthToken#load_user with appropriate blocks before adding it \
		to Kemal!"
    end
  end
end
