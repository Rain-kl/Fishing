package model

import "time"

const (
	HoneypotTypeSSH = "ssh"

	StatusRunning = "running"
	StatusStopped = "stopped"
	StatusError   = "error"

	EventAuthAttempt  = "auth_attempt"
	EventSessionOpen  = "session_open"
	EventCommand      = "command"
	EventSessionClose = "session_close"
)

// Honeypot represents a configured honeypot instance.
type Honeypot struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Port         int       `json:"port"`
	Username     string    `json:"username"`
	Password     string    `json:"password"`
	DesiredState string    `json:"desired_state"` // "running" or "stopped"
	CreatedAt    time.Time `json:"created_at"`
}

// HoneypotView enriches Honeypot with live runtime state and aggregated audit counters.
type HoneypotView struct {
	Honeypot
	Status           string     `json:"status"`
	ErrorMessage     string     `json:"error_message,omitempty"`
	ConnectionCount  int        `json:"connection_count"`
	AuthSuccessCount int        `json:"auth_success_count"`
	AuthFailureCount int        `json:"auth_failure_count"`
	CommandCount     int        `json:"command_count"`
	LastSeenAt       *time.Time `json:"last_seen_at,omitempty"`
}

// CreateHoneypotRequest defines the payload for creating a new honeypot.
type CreateHoneypotRequest struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Port     int    `json:"port"`
	Username string `json:"username"`
	Password string `json:"password"`
}

// LogEntry records an access event, authentication attempt, or executed command.
type LogEntry struct {
	ID            string    `json:"id"`
	SessionID     string    `json:"session_id"`
	HoneypotID    string    `json:"honeypot_id"`
	HoneypotName  string    `json:"honeypot_name"`
	HoneypotType  string    `json:"honeypot_type"`
	HoneypotPort  int       `json:"honeypot_port"`
	SourceIP      string    `json:"source_ip"`
	SourcePort    int       `json:"source_port,omitempty"`
	ClientVersion string    `json:"client_version,omitempty"`
	EventType     string    `json:"event_type"`
	Username      string    `json:"username,omitempty"`
	Password      string    `json:"password,omitempty"`
	AuthSuccess   *bool     `json:"auth_success,omitempty"`
	Command       string    `json:"command,omitempty"`
	Detail        string    `json:"detail,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// LogFilter filters queried audit logs.
type LogFilter struct {
	HoneypotID string
	EventType  string
	SourceIP   string
	Query      string
	Limit      int
}

// OverviewStats summarizes platform-wide telemetry.
type OverviewStats struct {
	TotalHoneypots   int    `json:"total_honeypots"`
	RunningHoneypots int    `json:"running_honeypots"`
	TotalConnections int    `json:"total_connections"`
	AuthSuccessCount int    `json:"auth_success_count"`
	AuthFailureCount int    `json:"auth_failure_count"`
	CommandCount     int    `json:"command_count"`
	UniqueIPCount    int    `json:"unique_ip_count"`
	Version          string `json:"version"`
}
