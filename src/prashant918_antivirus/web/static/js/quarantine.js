/**
 * Prashant918 Advanced Antivirus - Quarantine Management JavaScript
 * Handles quarantine operations, file management, and restoration
 */

class QuarantineManager {
    constructor() {
        this.socket = null;
        this.quarantineItems = [];
        this.selectedItems = new Set();
        this.currentPage = 1;
        this.itemsPerPage = 20;
        this.sortBy = 'date';
        this.sortDirection = 'desc';
        this.filters = {
            search: '',
            threatType: 'all',
            date: 'all'
        };
        
        this.init();
    }
    
    init() {
        this.initializeWebSocket();
        this.initializeEventListeners();
        this.loadQuarantineItems();
        this.updateOverviewStats();
        
        console.log('Quarantine Manager initialized');
    }
    
    initializeWebSocket() {
        try {
            this.socket = io();
            
            this.socket.on('connect', () => {
                console.log('Connected to antivirus server');
                this.updateConnectionStatus(true);
            });
            
            this.socket.on('disconnect', () => {
                console.log('Disconnected from antivirus server');
                this.updateConnectionStatus(false);
            });
            
            this.socket.on('quarantine_updated', (data) => {
                this.handleQuarantineUpdate(data);
            });
            
        } catch (error) {
            console.error('WebSocket initialization failed:', error);
            this.showNotification('Real-time updates unavailable', 'error');
        }
    }
    
    initializeEventListeners() {
        // Theme toggle
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => this.toggleTheme());
        }
        
        // Search and filters
        document.getElementById('searchQuarantine')?.addEventListener('input', (e) => {
            this.filters.search = e.target.value;
            this.applyFilters();
        });
        
        document.getElementById('threatTypeFilter')?.addEventListener('change', (e) => {
            this.filters.threatType = e.target.value;
            this.applyFilters();
        });
        
        document.getElementById('dateFilter')?.addEventListener('change', (e) => {
            this.filters.date = e.target.value;
            this.applyFilters();
        });
        
        // Control buttons
        document.getElementById('refreshQuarantine')?.addEventListener('click', () => this.loadQuarantineItems());
        document.getElementById('cleanupOld')?.addEventListener('click', () => this.cleanupOldItems());
        document.getElementById('deleteSelected')?.addEventListener('click', () => this.showDeleteConfirmation());
        document.getElementById('restoreSelected')?.addEventListener('click', () => this.restoreSelectedItems());
        
        // Bulk selection
        document.getElementById('selectAll')?.addEventListener('change', (e) => this.toggleSelectAll(e.target.checked));
        
        // Sorting
        document.getElementById('sortBy')?.addEventListener('change', (e) => {
            this.sortBy = e.target.value;
            this.sortItems();
        });
        
        document.getElementById('sortDirection')?.addEventListener('click', () => this.toggleSortDirection());
        
        // Modal controls
        this.setupModalEventListeners();
    }
    
    setupModalEventListeners() {
        // Item details modal
        document.getElementById('closeDetailsModal')?.addEventListener('click', () => this.hideModal('itemDetailsModal'));
        document.getElementById('closeDetails')?.addEventListener('click', () => this.hideModal('itemDetailsModal'));
        document.getElementById('restoreItem')?.addEventListener('click', () => this.restoreCurrentItem());
        document.getElementById('deleteItem')?.addEventListener('click', () => this.deleteCurrentItem());
        
        // Restore confirmation modal
        document.getElementById('closeRestoreModal')?.addEventListener('click', () => this.hideModal('restoreConfirmModal'));
        document.getElementById('cancelRestore')?.addEventListener('click', () => this.hideModal('restoreConfirmModal'));
        document.getElementById('confirmRestore')?.addEventListener('click', () => this.confirmRestore());
        
        // Delete confirmation modal
        document.getElementById('closeDeleteModal')?.addEventListener('click', () => this.hideModal('deleteConfirmModal'));
        document.getElementById('cancelDelete')?.addEventListener('click', () => this.hideModal('deleteConfirmModal'));
        document.getElementById('confirmDelete')?.addEventListener('click', () => this.confirmDelete());
        
        // Close modals on overlay click
        document.querySelectorAll('.modal-overlay').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('active');
                }
            });
        });
    }
    
    async loadQuarantineItems() {
        try {
            this.showLoading(true);
            
            const response = await fetch('/api/quarantine/list');
            if (!response.ok) {
                throw new Error('Failed to load quarantine items');
            }
            
            const data = await response.json();
            this.quarantineItems = data.items || this.generateSampleQuarantineItems();
            
            this.applyFilters();
            this.updateOverviewStats();
            
        } catch (error) {
            console.error('Failed to load quarantine items:', error);
            this.showNotification('Failed to load quarantine items: ' + error.message, 'error');
            
            // Use sample data as fallback
            this.quarantineItems = this.generateSampleQuarantineItems();
            this.applyFilters();
            this.updateOverviewStats();
            
        } finally {
            this.showLoading(false);
        }
    }
    
    generateSampleQuarantineItems() {
        const threatTypes = ['malware', 'virus', 'trojan', 'adware', 'suspicious'];
        const fileNames = [
            'suspicious_file.exe',
            'malware_sample.dll',
            'trojan_horse.bat',
            'adware_installer.msi',
            'virus_infected.doc',
            'keylogger.exe',
            'ransomware.pdf',
            'spyware.zip'
        ];
        
        const items = [];
        
        for (let i = 0; i < 15; i++) {
            const threatType = threatTypes[Math.floor(Math.random() * threatTypes.length)];
            const fileName = fileNames[Math.floor(Math.random() * fileNames.length)];
            const date = new Date();
            date.setDate(date.getDate() - Math.floor(Math.random() * 30));
            
            items.push({
                id: `quarantine_${i + 1}`,
                fileName: fileName,
                originalPath: `/home/user/Downloads/${fileName}`,
                quarantinePath: `/quarantine/${Date.now()}_${fileName}`,
                threatType: threatType,
                threatName: `${threatType.charAt(0).toUpperCase() + threatType.slice(1)}.Generic`,
                detectionMethod: 'ML Detection',
                fileSize: Math.floor(Math.random() * 10000000) + 1000,
                quarantineDate: date,
                status: 'quarantined',
                riskLevel: ['high', 'medium', 'low'][Math.floor(Math.random() * 3)],
                checksum: this.generateChecksum(),
                encrypted: true
            });
        }
        
        return items;
    }
    
    generateChecksum() {
        return Array.from({length: 64}, () => Math.floor(Math.random() * 16).toString(16)).join('');
    }
    
    applyFilters() {
        let filteredItems = [...this.quarantineItems];
        
        // Apply search filter
        if (this.filters.search) {
            const searchTerm = this.filters.search.toLowerCase();
            filteredItems = filteredItems.filter(item =>
                item.fileName.toLowerCase().includes(searchTerm) ||
                item.threatName.toLowerCase().includes(searchTerm) ||
                item.originalPath.toLowerCase().includes(searchTerm)
            );
        }
        
        // Apply threat type filter
        if (this.filters.threatType !== 'all') {
            filteredItems = filteredItems.filter(item =>
                item.threatType === this.filters.threatType
            );
        }
        
        // Apply date filter
        if (this.filters.date !== 'all') {
            const now = new Date();
            const filterDate = new Date();
            
            switch (this.filters.date) {
                case 'today':
                    filterDate.setHours(0, 0, 0, 0);
                    break;
                case 'week':
                    filterDate.setDate(now.getDate() - 7);
                    break;
                case 'month':
                    filterDate.setMonth(now.getMonth() - 1);
                    break;
            }
            
            filteredItems = filteredItems.filter(item =>
                new Date(item.quarantineDate) >= filterDate
            );
        }
        
        this.filteredItems = filteredItems;
        this.sortItems();
    }
    
    sortItems() {
        this.filteredItems.sort((a, b) => {
            let aValue, bValue;
            
            switch (this.sortBy) {
                case 'name':
                    aValue = a.fileName.toLowerCase();
                    bValue = b.fileName.toLowerCase();
                    break;
                case 'threat':
                    aValue = a.threatType.toLowerCase();
                    bValue = b.threatType.toLowerCase();
                    break;
                case 'size':
                    aValue = a.fileSize;
                    bValue = b.fileSize;
                    break;
                case 'date':
                default:
                    aValue = new Date(a.quarantineDate);
                    bValue = new Date(b.quarantineDate);
                    break;
            }
            
            if (aValue < bValue) return this.sortDirection === 'asc' ? -1 : 1;
            if (aValue > bValue) return this.sortDirection === 'asc' ? 1 : -1;
            return 0;
        });
        
        this.renderQuarantineList();
        this.updatePagination();
    }
    
    toggleSortDirection() {
        this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        
        const sortButton = document.getElementById('sortDirection');
        const icon = sortButton.querySelector('i');
        icon.className = this.sortDirection === 'asc' ? 'fas fa-sort-up' : 'fas fa-sort-down';
        
        this.sortItems();
    }
    
    renderQuarantineList() {
        const quarantineList = document.getElementById('quarantineList');
        if (!quarantineList) return;
        
        if (this.filteredItems.length === 0) {
            quarantineList.innerHTML = `
                <div class="empty-quarantine">
                    <i class="fas fa-shield-alt"></i>
                    <h3>No quarantined files</h3>
                    <p>Your system is clean! No threats have been quarantined recently.</p>
                </div>
            `;
            return;
        }
        
        const startIndex = (this.currentPage - 1) * this.itemsPerPage;
        const endIndex = startIndex + this.itemsPerPage;
        const pageItems = this.filteredItems.slice(startIndex, endIndex);
        
        quarantineList.innerHTML = pageItems.map(item => this.renderQuarantineItem(item)).join('');
        
        // Add event listeners to items
        quarantineList.querySelectorAll('.quarantine-item').forEach(itemElement => {
            const itemId = itemElement.dataset.itemId;
            
            // Item selection
            const checkbox = itemElement.querySelector('.item-checkbox input');
            checkbox.addEventListener('change', (e) => {
                if (e.target.checked) {
                    this.selectedItems.add(itemId);
                    itemElement.classList.add('selected');
                } else {
                    this.selectedItems.delete(itemId);
                    itemElement.classList.remove('selected');
                }
                this.updateSelectionUI();
            });
            
            // Item click (show details)
            itemElement.addEventListener('click', (e) => {
                if (!e.target.closest('.item-checkbox') && !e.target.closest('.item-actions')) {
                    this.showItemDetails(itemId);
                }
            });
            
            // Action buttons
            const restoreBtn = itemElement.querySelector('.action-btn.restore');
            const deleteBtn = itemElement.querySelector('.action-btn.delete');
            
            if (restoreBtn) {
                restoreBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.showRestoreConfirmation([itemId]);
                });
            }
            
            if (deleteBtn) {
                deleteBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    this.showDeleteConfirmation([itemId]);
                });
            }
        });
    }
    
    renderQuarantineItem(item) {
        const isSelected = this.selectedItems.has(item.id);
        
        return `
            <div class="quarantine-item ${isSelected ? 'selected' : ''}" data-item-id="${item.id}">
                <div class="item-checkbox">
                    <label class="checkbox-container">
                        <input type="checkbox" ${isSelected ? 'checked' : ''}>
                        <span class="checkmark"></span>
                    </label>
                </div>
                
                <div class="item-icon ${item.threatType}">
                    <i class="fas fa-${this.getThreatIcon(item.threatType)}"></i>
                </div>
                
                <div class="item-info">
                    <div class="item-name" title="${item.fileName}">${item.fileName}</div>
                    <div class="item-details">
                        <div class="item-detail">
                            <i class="fas fa-folder"></i>
                            <span title="${item.originalPath}">${this.truncatePath(item.originalPath, 40)}</span>
                        </div>
                        <div class="item-detail">
                            <i class="fas fa-virus"></i>
                            <span>${item.threatName}</span>
                        </div>
                        <div class="item-detail">
                            <i class="fas fa-weight-hanging"></i>
                            <span>${this.formatFileSize(item.fileSize)}</span>
                        </div>
                        <div class="item-detail">
                            <i class="fas fa-search"></i>
                            <span>${item.detectionMethod}</span>
                        </div>
                    </div>
                </div>
                
                <div class="item-meta">
                    <div class="threat-badge ${item.riskLevel}">${item.riskLevel.toUpperCase()}</div>
                    <div class="quarantine-date">${this.formatDate(item.quarantineDate)}</div>
                </div>
                
                <div class="item-actions">
                    <button class="action-btn restore" title="Restore file">
                        <i class="fas fa-undo"></i>
                    </button>
                    <button class="action-btn delete" title="Delete permanently">
                        <i class="fas fa-trash"></i>
                    </button>
                    <button class="action-btn info" title="View details">
                        <i class="fas fa-info-circle"></i>
                    </button>
                </div>
            </div>
        `;
    }
    
    getThreatIcon(threatType) {
        const icons = {
            malware: 'bug',
            virus: 'virus',
            trojan: 'horse-head',
            adware: 'ad',
            suspicious: 'question-circle'
        };
        return icons[threatType] || 'exclamation-triangle';
    }
    
    updateSelectionUI() {
        const selectedCount = this.selectedItems.size;
        
        // Update selection count
        const selectionCount = document.getElementById('selectionCount');
        if (selectionCount) {
            selectionCount.textContent = `${selectedCount} selected`;
        }
        
        // Update select all checkbox
        const selectAllCheckbox = document.getElementById('selectAll');
        if (selectAllCheckbox) {
            const totalVisible = document.querySelectorAll('.quarantine-item').length;
            selectAllCheckbox.checked = selectedCount > 0 && selectedCount === totalVisible;
            selectAllCheckbox.indeterminate = selectedCount > 0 && selectedCount < totalVisible;
        }
        
        // Update action buttons
        const deleteBtn = document.getElementById('deleteSelected');
        const restoreBtn = document.getElementById('restoreSelected');
        
        if (deleteBtn) {
            deleteBtn.disabled = selectedCount === 0;
        }
        
        if (restoreBtn) {
            restoreBtn.disabled = selectedCount === 0;
        }
    }
    
    toggleSelectAll(checked) {
        const visibleItems = document.querySelectorAll('.quarantine-item');
        
        if (checked) {
            visibleItems.forEach(item => {
                const itemId = item.dataset.itemId;
                this.selectedItems.add(itemId);
                item.classList.add('selected');
                const checkbox = item.querySelector('.item-checkbox input');
                if (checkbox) checkbox.checked = true;
            });
        } else {
            visibleItems.forEach(item => {
                const itemId = item.dataset.itemId;
                this.selectedItems.delete(itemId);
                item.classList.remove('selected');
                const checkbox = item.querySelector('.item-checkbox input');
                if (checkbox) checkbox.checked = false;
            });
        }
        
        this.updateSelectionUI();
    }
    
    showItemDetails(itemId) {
        const item = this.quarantineItems.find(i => i.id === itemId);
        if (!item) return;
        
        const itemDetails = document.getElementById('itemDetails');
        if (!itemDetails) return;
        
        itemDetails.innerHTML = `
            <div class="detail-section">
                <h4><i class="fas fa-file"></i> File Information</h4>
                <div class="detail-list">
                    <div class="detail-item">
                        <span class="detail-label">File Name:</span>
                        <span class="detail-value">${item.fileName}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Original Path:</span>
                        <span class="detail-value file-path">${item.originalPath}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">File Size:</span>
                        <span class="detail-value">${this.formatFileSize(item.fileSize)}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Checksum (SHA256):</span>
                        <span class="detail-value file-path">${item.checksum}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Encrypted:</span>
                        <span class="detail-value">${item.encrypted ? 'Yes' : 'No'}</span>
                    </div>
                </div>
            </div>
            
            <div class="detail-section">
                <h4><i class="fas fa-shield-alt"></i> Threat Information</h4>
                <div class="detail-list">
                    <div class="detail-item">
                        <span class="detail-label">Threat Type:</span>
                        <span class="detail-value">${item.threatType.toUpperCase()}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Threat Name:</span>
                        <span class="detail-value">${item.threatName}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Risk Level:</span>
                        <span class="detail-value">
                            <span class="threat-badge ${item.riskLevel}">${item.riskLevel.toUpperCase()}</span>
                        </span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Detection Method:</span>
                        <span class="detail-value">${item.detectionMethod}</span>
                    </div>
                    <div class="detail-item">
                        <span class="detail-label">Quarantine Date:</span>
                        <span class="detail-value">${this.formatDateTime(item.quarantineDate)}</span>
                    </div>
                </div>
            </div>
        `;
        
        // Store current item for modal actions
        this.currentItem = item;
        
        this.showModal('itemDetailsModal');
    }
    
    showRestoreConfirmation(itemIds = null) {
        const items = itemIds || Array.from(this.selectedItems);
        if (items.length === 0) return;
        
        const restoreFileInfo = document.getElementById('restoreFileInfo');
        if (restoreFileInfo) {
            if (items.length === 1) {
                const item = this.quarantineItems.find(i => i.id === items[0]);
                restoreFileInfo.innerHTML = `
                    <strong>File:</strong> ${item.fileName}<br>
                    <strong>Original Location:</strong> ${item.originalPath}<br>
                    <strong>Threat:</strong> ${item.threatName}
                `;
            } else {
                restoreFileInfo.innerHTML = `
                    <strong>${items.length} files</strong> will be restored to their original locations.
                `;
            }
        }
        
        this.itemsToRestore = items;
        this.showModal('restoreConfirmModal');
    }
    
    showDeleteConfirmation(itemIds = null) {
        const items = itemIds || Array.from(this.selectedItems);
        if (items.length === 0) return;
        
        const deleteCount = document.getElementById('deleteCount');
        if (deleteCount) {
            deleteCount.innerHTML = `
                <span class="count-number">${items.length}</span>
                <span class="count-label">${items.length === 1 ? 'file' : 'files'} will be permanently deleted</span>
            `;
        }
        
        this.itemsToDelete = items;
        this.showModal('deleteConfirmModal');
    }
    
    async confirmRestore() {
        if (!this.itemsToRestore || this.itemsToRestore.length === 0) return;
        
        try {
            this.showLoading(true);
            this.hideModal('restoreConfirmModal');
            
            for (const itemId of this.itemsToRestore) {
                const response = await fetch(`/api/quarantine/restore/${itemId}`, {
                    method: 'POST'
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.error || 'Restore failed');
                }
                
                // Remove from quarantine list
                this.quarantineItems = this.quarantineItems.filter(item => item.id !== itemId);
                this.selectedItems.delete(itemId);
            }
            
            this.showNotification(
                `Successfully restored ${this.itemsToRestore.length} file${this.itemsToRestore.length > 1 ? 's' : ''}`,
                'success'
            );
            
            this.applyFilters();
            this.updateOverviewStats();
            this.updateSelectionUI();
            
        } catch (error) {
            console.error('Failed to restore files:', error);
            this.showNotification('Failed to restore files: ' + error.message, 'error');
        } finally {
            this.showLoading(false);
            this.itemsToRestore = null;
        }
    }
    
    async confirmDelete() {
        if (!this.itemsToDelete || this.itemsToDelete.length === 0) return;
        
        try {
            this.showLoading(true);
            this.hideModal('deleteConfirmModal');
            
            for (const itemId of this.itemsToDelete) {
                const response = await fetch(`/api/quarantine/delete/${itemId}`, {
                    method: 'DELETE'
                });
                
                if (!response.ok) {
                    const error = await response.json();
                    throw new Error(error.
