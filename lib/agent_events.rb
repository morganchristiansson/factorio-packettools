# frozen_string_literal: true

# One bounded FIFO per agent; only decoded events, never packet buffers.
# Queue + worker are created lazily (guard against double-init); a nil
# queue at shutdown is a clean no-op (seen once in production).
module AgentEvents
  def initialize_events
    return if @event_queue
    @event_queue = SizedQueue.new(100)
    @event_worker = Thread.new do
      Thread.current.name = "#{self.class}-events"
      while (event = @event_queue.pop)
        method, args, kwargs = event
        begin
          public_send(method, *args, **kwargs)
        rescue StandardError => e
          warn "[#{self.class}] #{method} failed: #{e.class}: #{e.message}"
        end
      end
    end
  end

  def enqueue(method, *args, **kwargs)
    initialize_events
    @event_queue.push([method, args, kwargs], true)
    true
  rescue ThreadError, ClosedQueueError
    warn "[#{self.class}] event queue full or closed; dropped #{method}"
    false
  end

  def close_events
    # No queue ever created: nothing to drain.
    return unless @event_queue
    @event_queue.close
    # ponytail: pending events are not durable; add a spool if restart delivery matters.
    warn "[#{self.class}] shutdown with agent work still pending" unless @event_worker.join(2)
  end
end
