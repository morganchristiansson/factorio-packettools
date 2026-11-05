# frozen_string_literal: true

module FactorioProtocol
  # Base class for one network message's PARSER (msg_type 0-18). The parsed
  # message is #result — callers consume that hash, not this object.
  #
  # Subclasses implement #parse_body and populate #result:
  #   { header: {...}, <msg-specific key>: {...} }
  #
  # Decoding is owned by FactorioProtocol (Packet's subclasses call its
  # decode_* methods explicitly); this class owns only the header and the
  # parse lifecycle.
  class Packet
    attr_reader :data, :header, :result

    # `header:` lets the protocol-level dispatcher hand over the header it
    # already parsed — one header parse per datagram, not two.
    def self.parse(data, header: nil)
      new(data, header: header).parse
    end

    def initialize(data, header: nil)
      @data = data
      @header = header
      @result = nil
    end

    # Parse the network header (flags byte, optional message_id/fragments)
    # and dispatch to the subclass body. Returns self; callers read #result.
    def parse
      @header ||= FactorioProtocol.parse_network_header(@data)
      raise "not a factorio packet" unless @header
      @result = { header: @header }
      parse_body
      self
    end

    private

    def parse_body
      raise NotImplementedError
    end
  end
end
