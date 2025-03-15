document.addEventListener('DOMContentLoaded', function() {
    // Theme switcher with smooth transitions
    const themeSwitcher = document.getElementById('theme-switcher');
    if (themeSwitcher) {
        themeSwitcher.addEventListener('change', function() {
            // Apply transition class before theme change
            document.body.classList.add('theme-transition');
            
            fetch('/set-theme', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ theme: this.value })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    document.documentElement.setAttribute('data-theme', this.value);
                    // Remove transition class after animation completes
                    setTimeout(() => {
                        document.body.classList.remove('theme-transition');
                    }, 500);
                }
            })
            .catch(error => console.error('Error setting theme:', error));
        });
    }

    // Enhanced flash message handling with fade and close button
    const flashMessages = document.querySelectorAll('.alert');
    flashMessages.forEach(message => {
        // Auto-hide with smooth fade out
        setTimeout(() => {
            fadeOut(message);
        }, 5000);
        
        // Add close button functionality
        const closeBtn = message.querySelector('.close-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', function() {
                fadeOut(message);
            });
        }
    });

    // Fade out helper function
    function fadeOut(element) {
        element.style.opacity = '1';
        (function fade() {
            if ((element.style.opacity -= .1) < 0) {
                element.style.display = 'none';
                element.remove();
            } else {
                requestAnimationFrame(fade);
            }
        })();
    }

    // Improved form validation with better user feedback
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        // Add live validation on input blur
        Array.from(form.elements).forEach(input => {
            if (input.tagName !== 'BUTTON') {
                // Validate when user leaves a field
                input.addEventListener('blur', function() {
                    validateInput(this);
                });
                
                // Clear error state when user starts typing again
                input.addEventListener('input', function() {
                    if (this.classList.contains('invalid')) {
                        validateInput(this);
                    }
                });
            }
        });
        
        // Form submission validation
        form.addEventListener('submit', function(e) {
            let isValid = true;
            
            Array.from(form.elements).forEach(input => {
                if (input.tagName !== 'BUTTON' && !validateInput(input)) {
                    isValid = false;
                }
            });
            
            if (!isValid) {
                e.preventDefault();
                // Scroll to first invalid field
                const firstInvalid = form.querySelector('.invalid');
                if (firstInvalid) {
                    firstInvalid.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    firstInvalid.focus();
                }
            }
        });
    });
    
    // Input validation helper
    function validateInput(input) {
        // Skip non-required empty fields
        if (!input.required && input.value === '') {
            input.classList.remove('invalid');
            const errorMsg = input.nextElementSibling;
            if (errorMsg && errorMsg.classList.contains('error-message')) {
                errorMsg.remove();
            }
            return true;
        }
        
        if (!input.validity.valid) {
            input.classList.add('invalid');
            
            // Show error message
            let errorMsg = input.nextElementSibling;
            if (!errorMsg || !errorMsg.classList.contains('error-message')) {
                errorMsg = document.createElement('div');
                errorMsg.classList.add('error-message');
                input.parentNode.insertBefore(errorMsg, input.nextSibling);
            }
            
            // Set appropriate error message
            if (input.validity.valueMissing) {
                errorMsg.textContent = 'This field is required';
            } else if (input.validity.typeMismatch) {
                errorMsg.textContent = `Please enter a valid ${input.type}`;
            } else if (input.validity.patternMismatch) {
                errorMsg.textContent = input.title || 'Please match the requested format';
            } else if (input.validity.tooShort) {
                errorMsg.textContent = `Please use at least ${input.minLength} characters`;
            } else if (input.validity.tooLong) {
                errorMsg.textContent = `Please use no more than ${input.maxLength} characters`;
            } else {
                errorMsg.textContent = input.validationMessage;
            }
            
            return false;
        } else {
            input.classList.remove('invalid');
            const errorMsg = input.nextElementSibling;
            if (errorMsg && errorMsg.classList.contains('error-message')) {
                errorMsg.remove();
            }
            return true;
        }
    }

    // Enhanced organization fields toggle with animation
    const roleSelect = document.querySelector('select[name="role"]');
    const orgFields = document.querySelectorAll('.org-field');
    
    if (roleSelect && orgFields.length) {
        roleSelect.addEventListener('change', function() {
            toggleOrgFields(this.value);
        });
        
        // Initial state
        toggleOrgFields(roleSelect.value);
    }
    
    function toggleOrgFields(role) {
        orgFields.forEach(field => {
            if (role === 'organization') {
                field.style.display = 'block';
                // Add animation class
                setTimeout(() => field.classList.add('field-visible'), 10);
            } else {
                field.classList.remove('field-visible');
                // Wait for animation to complete before hiding
                setTimeout(() => {
                    if (!field.classList.contains('field-visible')) {
                        field.style.display = 'none';
                    }
                }, 300);
            }
        });
    }
    
    // Mobile menu toggle
    const mobileMenuToggle = document.querySelector('.mobile-menu-toggle');
    const navbarMenu = document.querySelector('.navbar-menu');
    
    if (mobileMenuToggle && navbarMenu) {
        mobileMenuToggle.addEventListener('click', function() {
            navbarMenu.classList.toggle('active');
            this.classList.toggle('active');
            
            // Toggle aria-expanded for accessibility
            const expanded = this.getAttribute('aria-expanded') === 'true' || false;
            this.setAttribute('aria-expanded', !expanded);
        });
    }
});