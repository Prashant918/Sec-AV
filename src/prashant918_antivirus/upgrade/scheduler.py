"""
Automated Update Scheduler
Handles scheduling and timing of automatic updates
"""

import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Callable, Any
import json
from pathlib import Path
from enum import Enum

from ..logger import SecureLogger
from ..config import SecureConfig
from ..exceptions import AntivirusError


class ScheduleType(Enum):
    """Types of update schedules"""
    IMMEDIATE = "immediate"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    CUSTOM = "custom"


class UpdatePriority(Enum):
    """Update priority levels"""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class ScheduledUpdate:
    """Represents a scheduled update"""
    
    def __init__(self, update_id: str, schedule_type: ScheduleType, 
                 priority: UpdatePriority, callback: Callable, **kwargs):
        self.update_id = update_id
        self.schedule_type = schedule_type
        self.priority = priority
        self.callback = callback
        self.created_at = datetime.now()
        self.last_run = None
        self.next_run = None
        self.run_count = 0
        self.enabled = True
        
        # Schedule-specific parameters
        self.schedule_params = kwargs
        
        # Calculate next run time
        self._calculate_next_run()
        
    def _calculate_next_run(self) -> None:
        """Calculate the next run time based on schedule type"""
        now = datetime.now()
        
        if self.schedule_type == ScheduleType.IMMEDIATE:
            self.next_run = now
        elif self.schedule_type == ScheduleType.DAILY:
            # Run at specified hour (default: 2 AM)
            hour = self.schedule_params.get('hour', 2)
            next_run = now.replace(hour=hour, minute=0, second=0, microsecond=0)
            if next_run <= now:
                next_run += timedelta(days=1)
            self.next_run = next_run
        elif self.schedule_type == ScheduleType.WEEKLY:
            # Run on specified day of week (default: Sunday)
            weekday = self.schedule_params.get('weekday', 6)  # 6 = Sunday
            hour = self.schedule_params.get('hour', 2)
            
            days_ahead = weekday - now.weekday()
            if days_ahead <= 0:  # Target day already happened this week
                days_ahead += 7
                
            next_run = now + timedelta(days=days_ahead)
            next_run = next_run.replace(hour=hour, minute=0, second=0, microsecond=0)
            self.next_run = next_run
        elif self.schedule_type == ScheduleType.MONTHLY:
            # Run on specified day of month (default: 1st)
            day = self.schedule_params.get('day', 1)
            hour = self.schedule_params.get('hour', 2)
            
            try:
                next_run = now.replace(day=day, hour=hour, minute=0, second=0, microsecond=0)
                if next_run <= now:
                    # Move to next month
                    if now.month == 12:
                        next_run = next_run.replace(year=now.year + 1, month=1)
                    else:
                        next_run = next_run.replace(month=now.month + 1)
                self.next_run = next_run
            except ValueError:
                # Handle invalid day (e.g., Feb 30)
                self.next_run = now + timedelta(days=30)
        elif self.schedule_type == ScheduleType.CUSTOM:
            # Custom interval in seconds
            interval = self.schedule_params.get('interval', 3600)  # Default: 1 hour
            self.next_run = now + timedelta(seconds=interval)
            
    def should_run(self) -> bool:
        """Check if the update should run now"""
        if not self.enabled:
            return False
            
        return self.next_run and datetime.now() >= self.next_run
        
    def mark_completed(self) -> None:
        """Mark the update as completed and calculate next run"""
        self.last_run = datetime.now()
        self.run_count += 1
        
        # Calculate next run time (except for immediate updates)
        if self.schedule_type != ScheduleType.IMMEDIATE:
            self._calculate_next_run()
        else:
            self.enabled = False  # Immediate updates run only once


class UpdateScheduler:
    """
    Manages scheduling and execution of automatic updates
    """
    
    def __init__(self):
        self.logger = SecureLogger("UpdateScheduler")
        self.config = SecureConfig()
        
        # Scheduler state
        self.running = False
        self.scheduler_thread = None
        self.scheduled_updates: Dict[str, ScheduledUpdate] = {}
        
        # Configuration
        self.check_interval = self.config.get('scheduler.check_interval', 60)  # 1 minute
        self.max_concurrent_updates = self.config.get('scheduler.max_concurrent', 1)
        self.maintenance_window_start = self.config.get('scheduler.maintenance_start', 2)  # 2 AM
        self.maintenance_window_end = self.config.get('scheduler.maintenance_end', 4)    # 4 AM
        
        # Persistence
        self.schedule_file = Path.home() / '.prashant918_antivirus' / 'scheduled_updates.json'
        self.schedule_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Thread safety
        self.lock = threading.Lock()
        
        # Running updates tracking
        self.running_updates: Dict[str, threading.Thread] = {}
        
        # Load persisted schedules
        self._load_schedules()
        
    def start_scheduler(self) -> None:
        """Start the update scheduler"""
        with self.lock:
            if self.running:
                self.logger.warning("Scheduler already running")
                return
                
            self.running = True
            self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
            self.scheduler_thread.start()
            
            self.logger.info("Update scheduler started")
            
    def stop_scheduler(self) -> None:
        """Stop the update scheduler"""
        with self.lock:
            if not self.running:
                return
                
            self.running = False
            
            # Wait for running updates to complete
            for update_id, thread in list(self.running_updates.items()):
                if thread.is_alive():
                    self.logger.info(f"Waiting for update {update_id} to complete...")
                    thread.join(timeout=30)  # Wait up to 30 seconds
                    
            if self.scheduler_thread and self.scheduler_thread.is_alive():
                self.scheduler_thread.join(timeout=10)
                
            self.logger.info("Update scheduler stopped")
            
    def schedule_update(self, update_id: str, schedule_type: ScheduleType, 
                       priority: UpdatePriority, callback: Callable, **kwargs) -> bool:
        """Schedule a new update"""
        try:
            with self.lock:
                if update_id in self.scheduled_updates:
                    self.logger.warning(f"Update {update_id} already scheduled")
                    return False
                    
                scheduled_update = ScheduledUpdate(
                    update_id, schedule_type, priority, callback, **kwargs
                )
                
                self.scheduled_updates[update_id] = scheduled_update
                
                # Persist schedules
                self._save_schedules()
                
                self.logger.info(
                    f"Scheduled update {update_id} ({schedule_type.value}) "
                    f"for {scheduled_update.next_run}"
                )
                
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to schedule update {update_id}: {e}")
            return False
            
    def unschedule_update(self, update_id: str) -> bool:
        """Remove a scheduled update"""
        try:
            with self.lock:
                if update_id not in self.scheduled_updates:
                    self.logger.warning(f"Update {update_id} not found in schedule")
                    return False
                    
                # Stop if currently running
                if update_id in self.running_updates:
                    self.logger.info(f"Stopping running update {update_id}")
                    # Note: We can't forcefully stop a thread, but we can mark it as disabled
                    self.scheduled_updates[update_id].enabled = False
                    
                del self.scheduled_updates[update_id]
                
                # Persist schedules
                self._save_schedules()
                
                self.logger.info(f"Unscheduled update {update_id}")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to unschedule update {update_id}: {e}")
            return False
            
    def _scheduler_loop(self) -> None:
        """Main scheduler loop"""
        while self.running:
            try:
                self._check_and_run_updates()
                self._cleanup_completed_updates()
                
                time.sleep(self.check_interval)
                
            except Exception as e:
                self.logger.error(f"Error in scheduler loop: {e}")
                time.sleep(60)  # Wait longer on error
                
    def _check_and_run_updates(self) -> None:
        """Check for updates that should run and execute them"""
        try:
            with self.lock:
                # Get updates that should run, sorted by priority
                ready_updates = []
                
                for update_id, scheduled_update in self.scheduled_updates.items():
                    if (scheduled_update.should_run() and 
                        update_id not in self.running_updates and
                        self._is_in_maintenance_window()):
                        
                        ready_updates.append((update_id, scheduled_update))
                        
                # Sort by priority (critical first)
                priority_order = {
                    UpdatePriority.CRITICAL: 0,
                    UpdatePriority.HIGH: 1,
                    UpdatePriority.NORMAL: 2,
                    UpdatePriority.LOW: 3
                }
                
                ready_updates.sort(key=lambda x: priority_order.get(x[1].priority, 3))
                
                # Run updates up to the concurrent limit
                for update_id, scheduled_update in ready_updates[:self.max_concurrent_updates]:
                    if len(self.running_updates) >= self.max_concurrent_updates:
                        break
                        
                    self._run_update(update_id, scheduled_update)
                    
        except Exception as e:
            self.logger.error(f"Error checking updates: {e}")
            
    def _is_in_maintenance_window(self) -> bool:
        """Check if current time is within maintenance window"""
        try:
            current_hour = datetime.now().hour
            
            if self.maintenance_window_start <= self.maintenance_window_end:
                # Same day window (e.g., 2 AM to 4 AM)
                return self.maintenance_window_start <= current_hour < self.maintenance_window_end
            else:
                # Cross-midnight window (e.g., 23:00 to 02:00)
                return (current_hour >= self.maintenance_window_start or 
                       current_hour < self.maintenance_window_end)
                       
        except Exception as e:
            self.logger.error(f"Error checking maintenance window: {e}")
            return True  # Default to allowing updates
            
    def _run_update(self, update_id: str, scheduled_update: ScheduledUpdate) -> None:
        """Run a scheduled update in a separate thread"""
        try:
            self.logger.info(f"Starting scheduled update: {update_id}")
            
            def update_wrapper():
                try:
                    # Execute the update callback
                    scheduled_update.callback()
                    
                    # Mark as completed
                    scheduled_update.mark_completed()
                    
                    self.logger.info(f"Completed scheduled update: {update_id}")
                    
                except Exception as e:
                    self.logger.error(f"Scheduled update {update_id} failed: {e}")
                    
                finally:
                    # Remove from running updates
                    with self.lock:
                        if update_id in self.running_updates:
                            del self.running_updates[update_id]
                            
            # Start update thread
            update_thread = threading.Thread(target=update_wrapper, daemon=True)
            self.running_updates[update_id] = update_thread
            update_thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start update {update_id}: {e}")
            
    def _cleanup_completed_updates(self) -> None:
        """Clean up completed update threads"""
        try:
            with self.lock:
                completed_updates = []
                
                for update_id, thread in self.running_updates.items():
                    if not thread.is_alive():
                        completed_updates.append(update_id)
                        
                for update_id in completed_updates:
                    del self.running_updates[update_id]
                    
        except Exception as e:
            self.logger.error(f"Error cleaning up completed updates: {e}")
            
    def _save_schedules(self) -> None:
        """Save scheduled updates to disk"""
        try:
            schedule_data = {}
            
            for update_id, scheduled_update in self.scheduled_updates.items():
                schedule_data[update_id] = {
                    'schedule_type': scheduled_update.schedule_type.value,
                    'priority': scheduled_update.priority.value,
                    'created_at': scheduled_update.created_at.isoformat(),
                    'last_run': scheduled_update.last_run.isoformat() if scheduled_update.last_run else None,
                    'next_run': scheduled_update.next_run.isoformat() if scheduled_update.next_run else None,
                    'run_count': scheduled_update.run_count,
                    'enabled': scheduled_update.enabled,
                    'schedule_params': scheduled_update.schedule_params
                }
                
            with open(self.schedule_file, 'w') as f:
                json.dump(schedule_data, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save schedules: {e}")
            
    def _load_schedules(self) -> None:
        """Load scheduled updates from disk"""
        try:
            if not self.schedule_file.exists():
                return
                
            with open(self.schedule_file, 'r') as f:
                schedule_data = json.load(f)
                
            for update_id, data in schedule_data.items():
                try:
                    # Note: We can't restore the callback function from disk
                    # This would need to be re-registered by the application
                    self.logger.debug(f"Found persisted schedule for {update_id}")
                    
                except Exception as e:
                    self.logger.warning(f"Failed to load schedule for {update_id}: {e}")
                    
        except Exception as e:
            self.logger.error(f"Failed to load schedules: {e}")
            
    def get_schedule_status(self) -> Dict[str, Any]:
        """Get current scheduler status"""
        with self.lock:
            return {
                'running': self.running,
                'scheduled_updates_count': len(self.scheduled_updates),
                'running_updates_count': len(self.running_updates),
                'maintenance_window': {
                    'start': self.maintenance_window_start,
                    'end': self.maintenance_window_end,
                    'in_window': self._is_in_maintenance_window()
                },
                'next_update': self._get_next_update_time(),
                'scheduled_updates': {
                    update_id: {
                        'schedule_type': update.schedule_type.value,
                        'priority': update.priority.value,
                        'next_run': update.next_run.isoformat() if update.next_run else None,
                        'last_run': update.last_run.isoformat() if update.last_run else None,
                        'run_count': update.run_count,
                        'enabled': update.enabled
                    }
                    for update_id, update in self.scheduled_updates.items()
                }
            }
            
    def _get_next_update_time(self) -> Optional[str]:
        """Get the time of the next scheduled update"""
        try:
            next_times = [
                update.next_run for update in self.scheduled_updates.values()
                if update.next_run and update.enabled
            ]
            
            if next_times:
                return min(next_times).isoformat()
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting next update time: {e}")
            return None
