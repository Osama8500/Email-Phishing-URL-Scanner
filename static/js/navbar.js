// التحكم في القوائم المنسدلة
document.addEventListener('DOMContentLoaded', function() {
    // التحكم في القوائم المنسدلة
    const dropdowns = document.querySelectorAll('.dropdown');
    
    dropdowns.forEach(dropdown => {
        const button = dropdown.querySelector('.dropdown-toggle');
        const menu = dropdown.querySelector('.dropdown-menu');
        
        if (button && menu) {
            button.addEventListener('click', (e) => {
                e.stopPropagation();
                
                // إغلاق جميع القوائم المنسدلة الأخرى
                dropdowns.forEach(otherDropdown => {
                    if (otherDropdown !== dropdown) {
                        otherDropdown.querySelector('.dropdown-menu')?.classList.remove('show');
                    }
                });
                
                // تبديل حالة القائمة الحالية
                menu.classList.toggle('show');
            });
        }
    });
    
    // إغلاق القوائم المنسدلة عند النقر خارجها
    document.addEventListener('click', (e) => {
        if (!e.target.closest('.dropdown')) {
            document.querySelectorAll('.dropdown-menu').forEach(menu => {
                menu.classList.remove('show');
            });
        }
    });
    
    // التحكم في قائمة الإشعارات
    const notificationsBtn = document.querySelector('.notification-btn');
    const notificationsDropdown = document.querySelector('.notifications-dropdown');
    
    if (notificationsBtn && notificationsDropdown) {
        notificationsBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            notificationsDropdown.classList.toggle('show');
        });
    }
    
    // التحكم في قائمة الملف الشخصي
    const profileBtn = document.querySelector('.profile-btn');
    const profileDropdown = profileBtn?.closest('.dropdown')?.querySelector('.dropdown-menu');
    
    if (profileBtn && profileDropdown) {
        profileBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            profileDropdown.classList.toggle('show');
        });
    }
    
    // إغلاق القوائم عند النقر على أي رابط داخلها
    document.querySelectorAll('.dropdown-item').forEach(item => {
        item.addEventListener('click', () => {
            document.querySelectorAll('.dropdown-menu').forEach(menu => {
                menu.classList.remove('show');
            });
        });
    });
}); 