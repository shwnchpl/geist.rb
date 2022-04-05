#!/usr/bin/env ruby

# Copyright 2022 Shawn M. Chapla <shawn@chapla.email>
# 
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
# 
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

require 'base64'
require 'digest'
require 'fileutils'
require 'optparse'
require 'rouge'
require 'set'
require 'webrick'

# FIXME: Figure out where this actually belongs.
module Geist
  VERSION = "0.1.0"
end

module Util
  def Util::gen_hash(contents)
    return Base64.urlsafe_encode64(Base64.decode64(
      Digest::SHA256.base64digest(contents)
    ))[0..7]
  end

  def Util::gen_html_response(res, preq)
    file_lines = preq.file_contents.count("\n")
    line_no_padding = Math.log10(file_lines).to_i + 1
    formatter = Rouge::Formatters::HTMLTable.new(
      Rouge::Formatters::HTML.new(),
      {
        :line_format => "%#{line_no_padding}i",
      }
    )
    lexer = Rouge::Lexer.guess({
      :filename => preq.file_name,
      :source => preq.file_contents
    })

    l = Util::gen_link(preq, 'f')
    raw_file_link = "<a href=\"#{l}\">raw</a>"
    file_ctime = File::Stat.new(preq.file_path).ctime

    res.status = 200
    res.content_type = 'text/html'
    res.body = <<~END_HTML
        <!doctype html public "-//w3c//dtd html 4.0//en">
        <html>
        <head><style type="text/css" media="screen">
        #{Rouge::Themes::Base16.mode(:light).render(scope: '.highlight')}
        .highlight .rouge-gutter {
          background-color: #d3d3d3;
        }
        </style></head>
        <body>
        <span class="highlight">
        #{formatter.format(lexer.lex(preq.file_contents))}
        </span>
        <p>#{preq.file_name} | modified: #{file_ctime} | #{raw_file_link}</p>
        </body>
        </html>
    END_HTML
  end

  def Util::gen_link(preq, type)
    return [
      "http://#{preq.req.host}",
      preq.req.port != 80 ? ":#{preq.req.port}" : '',
      "/#{type}/#{preq.file_hash}/#{preq.file_name}"
    ].join
  end
end

module ParsedReq
  class ParsedReq::Get
    attr_reader :file_contents, :file_hash, :file_name, :file_path, :req, :type

    def initialize(req, conf, logger)
      @is_valid = false
      @req = req

      # Request must be of the format 'f|g/hash/filename'. If it is not,
      # then this is not a valid request.
      split_path = req.path.split('/')
      if split_path.length != 4 or (split_path[1] != 'f' and
          split_path[1] != 'g') or split_path[2].length != 8
        logger.info("Bad request.")
        return
      end

      _, @type, req_hash, @file_name = split_path

      # Attempt to read the file. If we can't read it, this link can't
      # possibly be valid.
      @file_path = "#{conf.fs_path}/#{req_hash}-#{@file_name}"
      begin
        @file_contents = File.read(@file_path)
      rescue StandardError => _
        logger.info('Failed to read requested file:')
        logger.info("    #{@file_path}")
        return
      end

      @file_hash = Util::gen_hash(@file_contents)
      if req_hash != @file_hash
        logger.warn('Read requested file, but hash differs.')
        logger.warn("    Requested: #{req_hash}")
        logger.warn("    Actual: #{@file_hash}")
        logger.warn('This may imply corruption in the file store.')
        return
      end

      @is_valid = true
    end

    def valid?
      return @is_valid
    end
  end

  class ParsedReq::Post
    attr_reader :content_length, :file_contents, :file_hash, :file_name, \
      :file_path, :req

    def initialize(req, conf, logger)
      @is_valid = false
      @req = req

      @file_name = nil
      if data = req.query['data']
        @file_name = data.filename
      end
      req_secret = req['GeistApiKey']

      if data == nil or @file_name == nil or req_secret == nil
        logger.info('Incomplete POST request.')
        return
      end

      unless conf.valid_keys.include? req_secret
        logger.info('Bad secret.')
        return
      end

      @content_length = req['content-length'].to_i
      @file_contents = data.to_s
      @file_hash = Util::gen_hash(@file_contents)
      @file_path = "#{conf.fs_path}/#{@file_hash}-#{@file_name}"

      @is_valid = true
    end

    def valid?
      return @is_valid
    end
  end
end

class GeistServlet < WEBrick::HTTPServlet::AbstractServlet
  def initialize(server, config)
    @giest_conf = config
    @logger = server.logger
    super
  end

  def do_GET(req, res)
    preq = ParsedReq::Get.new(req, @giest_conf, @logger)

    if preq.valid?
      if preq.type == 'g'
        Util::gen_html_response(res, preq)
      else
        res.status = WEBrick::HTTPStatus::RC_OK
        res.content_type = 'text/plain'
        res.body = preq.file_contents
      end
    else
      raise WEBrick::HTTPStatus::BadRequest
    end
  end

  def do_POST(req, res)
    res.content_type = 'text/plain'

    preq = ParsedReq::Post.new(req, @giest_conf, @logger)
    unless preq.valid?
      raise WEBrick::HTTPStatus::BadRequest
    end

    if preq.content_length > @giest_conf.file_size_limit
      res.status = WEBrick::HTTPStatus::RC_FORBIDDEN
      res.body = "File exceeds size limit: #{@giest_conf.file_size_limit}"
      return
    end

    if File.exist? preq.file_path
      res.status = WEBrick::HTTPStatus::RC_CONFLICT
      res.body = 'File already exists: '
    else
      begin
        f = File.open(preq.file_path, 'w')
        f.write(preq.file_contents)
        f.close()
      rescue StandardError => e
        @logger.error('Unexpected file exception:')
        @logger.error("    #{e}")
        raise WEBrick::HTTPStatus::InternalServerError
      end
      res.status = WEBrick::HTTPStatus::RC_OK
      res.body = ''
    end

    res.body += "#{Util::gen_link(preq, 'g')}\n"
  end
end

# XXX: Semi-hack to override the default WEBrick error page with
# something much simpler.
module WEBrick
  class HTTPResponse
    def create_error_page
      @content_type = 'text/plain'
      @body = "#{@status}: #{@reason_phrase}\n"
    end
  end
end

class GeistConfig
  attr_reader :file_size_limit, :valid_keys, :fs_path, :port

  def initialize
    @file_size_limit = 100000
    # FIXME: Dir.home may fail when running in systemd on certain older
    # systems. It would be preferable to use something more robust.
    @key_file_path = "#{Dir.home}/.geist-keys"
    @fs_path = '_f'
    @port = 8080
    @valid_keys = Set[]
  end

  def parse_opts
    OptionParser.new do |opts|
      opts.banner = 'Usage: geist.rb [options]'

      opts.on('-h', '--help', 'Display this help.') do
        $stderr.puts opts
        exit -1
      end

      opts.on('-l', '--limit-size N', 'Limit upload size to N bytes.') do |n|
        @file_size_limit = n.to_i
      end

      opts.on('-k', '--keys PATH', 'Path to secret keys file.') do |p|
        @key_file_path = p
      end

      opts.on('-f', '--file-store PATH', 'Path to file store dir.') do |p|
        @fs_path = p
      end

      opts.on('-p', '--port PORT', 'Port upon which to run.') do |p|
        @port = p.to_i
      end
    end.parse!
  end

  def load_keys
    if !File.file? @key_file_path
      $stderr.puts "Error: key file #{@key_file_path} does not exist."
      exit -1
    else
      @valid_keys = File.readlines(@key_file_path, chomp: true).to_set
    end
  end

  def create_dirs
    FileUtils.mkdir_p @fs_path
  end

  def dump(logger)
    self.instance_variables.each do |v|
      unless v == :@valid_keys
        logger.info("    #{v}: #{self.instance_variable_get(v)}")
      end
    end
  end
end

if $PROGRAM_NAME == __FILE__
  config = GeistConfig.new

  config.parse_opts
  config.load_keys
  config.create_dirs

  # Parse command line arguments.
  server = WEBrick::HTTPServer.new(:Port => config.port)
  server.mount("/", GeistServlet, config)

  server.logger.info('Starting Geist server with the following config:')
  config.dump(server.logger)

  Signal.trap 'INT' do
    server.shutdown
  end

  server.start
end
