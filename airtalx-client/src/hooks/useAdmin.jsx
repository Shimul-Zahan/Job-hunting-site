import { useContext, useState, useEffect } from "react";
import { AuthContext } from "../providers/AuthProviders";

const useAdmin = () => {
    const { user } = useContext(AuthContext);
    const [isAdmin, setIsAdmin] = useState(false);
    const [isLoading, setIsLoading] = useState(true);

    useEffect(() => {
        const fetchAdminStatus = async () => {
            try {
                const response = await fetch(`/users/admin/${user?.email}`);
                if (!response.ok) {
                    throw new Error('Failed to fetch admin status');
                }
                const data = await response.json();
                setIsAdmin(data.admin);
            } catch (error) {
                console.error('Error fetching admin status:', error);
            } finally {
                setIsLoading(false);
            }
        };

        if (user) {
            fetchAdminStatus();
        } else {
            setIsLoading(false);
        }
    }, [user]);

    return [isAdmin, isLoading];
};

export default useAdmin;
