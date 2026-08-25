# frozen_string_literal: true

module EndpointSecurity
  # A retained Endpoint Security message delivered to a handler.
  class Message
    # @return [Time]
    def deadline_at
      Time.now + time_left
    end

    # @return [Hash]
    def to_h
      {
        version: version,
        event_type: event_type,
        action_type: action_type,
        time: time,
        mach_time: mach_time,
        deadline: deadline,
        seq_num: seq_num,
        global_seq_num: global_seq_num,
        process: process&.to_h,
        thread: thread&.to_h,
        event: event&.to_h
      }
    end
  end
end
