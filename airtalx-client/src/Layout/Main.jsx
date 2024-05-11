import { Outlet } from 'react-router-dom';
import Footer from '../pages/Shared/Footer';
import Navbar from '../pages/Shared/Navbar';

const Main = () => {
    return (
        <div>
            <Navbar />
            <div className='pt-24 min-h-[81vh]'>
                <Outlet />
            </div>
            <Footer/>
        </div>
    );
};

export default Main;